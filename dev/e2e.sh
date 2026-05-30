#!/bin/sh
set -eu

POD="arachne-e2e"
TIMEOUT=60

cleanup() {
    kubectl delete pod "$POD" --ignore-not-found --wait=false -o name 2>/dev/null || true
}
trap cleanup EXIT
trap 'trap - INT; cleanup; exit 130' INT

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
spec:
  containers:
    - name: pause
      image: busybox:1.36
      command: ["sleep", "infinity"]
  restartPolicy: Never
EOF

i=0
while [ $i -lt $TIMEOUT ]; do
    PHASE=$(kubectl get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)
    IP=$(kubectl get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null)
    printf "\r[%ds] phase=%-12s ip=%-16s" "$i" "${PHASE:-unknown}" "${IP:--}"

    if [ -n "$IP" ]; then
        printf "\n"
        case "$IP" in
            10.244.*) ;;
            *)
                echo "FAIL: $POD got IP $IP (not in 10.244.0.0/16)"
                exit 1
                ;;
        esac
        echo "PASS (ADD): $POD got IP $IP"

        kubectl delete pod "$POD" --wait=false 2>/dev/null || true
        j=0
        while [ $j -lt $TIMEOUT ]; do
            PHASE=$(kubectl get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "gone")
            printf "\r[%ds] deleting phase=%-12s" "$j" "$PHASE"
            if [ "$PHASE" = "gone" ]; then
                printf "\n"
                echo "PASS (DEL): $POD terminated cleanly"
                exit 0
            fi
            sleep 1
            j=$((j + 1))
        done
        printf "\n"
        echo "FAIL: $POD stuck in Terminating after ${TIMEOUT}s"
        kubectl describe pod "$POD" 2>/dev/null || true
        exit 1
    fi

    sleep 1
    i=$((i + 1))
done

printf "\n"
echo "--- pod status ---"
kubectl describe pod "$POD" 2>/dev/null || true
echo "--- node status ---"
kubectl get nodes 2>/dev/null || true
echo "FAIL: timed out after ${TIMEOUT}s"
exit 1
