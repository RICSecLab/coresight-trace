#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

SCRIPT_DIR="$(cd $(dirname "${BASH_SOURCE[0]}"); pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.."; pwd)"

TRACER=${TRACER:-"${ROOT_DIR}/proc-trace"}
TRACER_ARGS=${TRACER_ARGS:-""}

TRACEE="${ROOT_DIR}/tests/fib-num"
SIZES="0x1000 0x10000 0x100000 0x1000000"

ARTIFACTS="cstrace.bin decoderargs.txt"

TRIALS=3
#TRIALS=1
OUTPUT="${ROOT_DIR}/bench/$(date "+%Y-%m-%d")"

main() {
  mkdir -p "${OUTPUT}"
  rm -f "${OUTPUT}/*.dat"
  exec > >(tee "${OUTPUT}/$(basename $0).log") 2>&1

  for num in $(seq 1 "${TRIALS}"); do
    for size in $SIZES; do
      run $num $size
    done
  done

  bash "${SCRIPT_DIR}/fib-plot.sh" "${OUTPUT}"
}

run() {
  native  "$@"
  tracing "$@" "0"
  tracing "$@" "1"
}

native() {
  local num=$1
  local size=$2

  echo "$(tput bold)== native (size:$size #$num) ==$(tput sgr0)"
  /usr/bin/time taskset 0x00000001 ${TRACEE} $size \
    |& tee ${OUTPUT}/native-$size-$num.dat
}

tracing() {
  local num=$1
  local size=$2
  local tracing_flag=$3

  case "$tracing_flag" in
    "0") trace="disable" ;;
    "1") trace="enable" ;;
  esac

  rm -f ${ARTIFACTS}

  echo "$(tput bold)== tracing $trace (size:$size #$num) ==$(tput sgr0)"
  /usr/bin/time sudo ${TRACER} ${TRACER_ARGS} --tracing=$tracing_flag -- \
    ${TRACEE} $size \
    |& tee ${OUTPUT}/tracing-$trace-$size-$num.dat

  rm -f ${ARTIFACTS}
}

main
