# .bashrc -- alice
cleanup() {
    rm -f /tmp/.cache-marker
}
trap cleanup EXIT
