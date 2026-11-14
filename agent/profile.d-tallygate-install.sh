# shellcheck shell=bash
# tallygate: put packages installed with `tallygate install` (rootless, see `tallygate install --help`)
# on PATH. Everything lives under the agent's home volume; nothing here writes to the read-only root
# filesystem. entrypoint.sh sources this too, so the consoles it starts see the same environment.
__tg_root="${HOME:-/home/agent}/.local/tallygate/root"
if [ -d "$__tg_root" ]; then
  case "$(dpkg --print-architecture 2>/dev/null)" in
    amd64) __tg_triplet=x86_64-linux-gnu ;;
    arm64) __tg_triplet=aarch64-linux-gnu ;;
    *) __tg_triplet= ;;
  esac
  PATH="$__tg_root/usr/bin:$__tg_root/usr/sbin:$__tg_root/bin:$__tg_root/sbin:$PATH"
  export PATH
  for __tg_lib in \
    "$__tg_root/usr/lib/$__tg_triplet" "$__tg_root/usr/lib" \
    "$__tg_root/lib/$__tg_triplet" "$__tg_root/lib"; do
    [ -n "${__tg_triplet}" ] || continue
    [ -d "$__tg_lib" ] || continue
    LD_LIBRARY_PATH="$__tg_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  done
  [ -n "${LD_LIBRARY_PATH:-}" ] && export LD_LIBRARY_PATH
  # Python packages installed from apt land in dist-packages; add it if present.
  for __tg_py in "$__tg_root"/usr/lib/python3*/dist-packages; do
    [ -d "$__tg_py" ] && PYTHONPATH="$__tg_py${PYTHONPATH:+:$PYTHONPATH}"
  done
  [ -n "${PYTHONPATH:-}" ] && export PYTHONPATH
  unset __tg_lib __tg_py __tg_triplet
fi
unset __tg_root
