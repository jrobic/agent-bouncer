#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' "usage: $0 --name <name> --repo <owner/repo> --version <version> --desc <description> --homepage <url> --license <license> --assets <dir> --target <target> [--target <target> ...] [--caveats-file <path>]" >&2
  printf '%s\n' 'A caveats file may use ${PREFIX} for #{HOMEBREW_PREFIX}.' >&2
}

usage_exit_2() {
  usage
  exit 2
}

require_value() {
  [ "$#" -ge 2 ] || usage_exit_2
  case "$2" in
    --*) usage_exit_2 ;;
  esac
}

ruby_string() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/#{/\\#{/g'
}

name=''
repo=''
version=''
description=''
homepage=''
license=''
assets=''
caveats_file=''
targets=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      require_value "$@"
      name=$2
      shift 2
      ;;
    --repo)
      require_value "$@"
      repo=$2
      shift 2
      ;;
    --version)
      require_value "$@"
      version=$2
      shift 2
      ;;
    --desc)
      require_value "$@"
      description=$2
      shift 2
      ;;
    --homepage)
      require_value "$@"
      homepage=$2
      shift 2
      ;;
    --license)
      require_value "$@"
      license=$2
      shift 2
      ;;
    --assets)
      require_value "$@"
      assets=$2
      shift 2
      ;;
    --target)
      require_value "$@"
      targets[${#targets[@]}]=$2
      shift 2
      ;;
    --caveats-file)
      require_value "$@"
      caveats_file=$2
      shift 2
      ;;
    *)
      usage_exit_2
      ;;
  esac
done

if [ -z "$name" ] || [ -z "$repo" ] || [ -z "$version" ] || [ -z "$description" ] || [ -z "$homepage" ] || [ -z "$license" ] || [ -z "$assets" ] || [ "${#targets[@]}" -eq 0 ]; then
  usage_exit_2
fi

if [ -n "$caveats_file" ] && [ ! -f "$caveats_file" ]; then
  printf 'error: missing caveats file: %s\n' "$caveats_file" >&2
  exit 1
fi

formula_class=$(printf '%s\n' "$name" | awk -F- '{ for (i = 1; i <= NF; i++) $i = toupper(substr($i, 1, 1)) substr($i, 2); printf "%s", $1; for (i = 2; i <= NF; i++) printf "%s", $i }')
asset_names=()
checksums=()
os_blocks=()
cpu_blocks=()
supported_platforms=''

for target in "${targets[@]}"; do
  case "$target" in
    darwin-arm64)
      os_block='macos'
      cpu_block='arm'
      platform_label='macOS Apple Silicon'
      ;;
    darwin-x64)
      os_block='macos'
      cpu_block='intel'
      platform_label='macOS Intel'
      ;;
    linux-x64)
      os_block='linux'
      cpu_block='intel'
      platform_label='Linux x64'
      ;;
    linux-arm64)
      os_block='linux'
      cpu_block='arm'
      platform_label='Linux arm64'
      ;;
    *)
      printf 'error: unsupported target: %s\n' "$target" >&2
      exit 2
      ;;
  esac

  asset_name="${name}-${version}-${target}.tar.gz"
  checksum_file="${assets}/${asset_name}.sha256"
  if [ ! -f "$checksum_file" ]; then
    printf 'error: missing checksum: %s\n' "$checksum_file" >&2
    exit 1
  fi

  checksum=$(awk 'NR == 1 { print $1; exit }' "$checksum_file")
  if [ -z "$checksum" ]; then
    printf 'error: missing checksum: %s\n' "$checksum_file" >&2
    exit 1
  fi

  if [ -n "$supported_platforms" ]; then
    supported_platforms="${supported_platforms}, ${platform_label}"
  else
    supported_platforms=$platform_label
  fi
  asset_names[${#asset_names[@]}]=$asset_name
  checksums[${#checksums[@]}]=$checksum
  os_blocks[${#os_blocks[@]}]=$os_block
  cpu_blocks[${#cpu_blocks[@]}]=$cpu_block
done

escaped_description=$(ruby_string "$description")
escaped_homepage=$(ruby_string "$homepage")
escaped_license=$(ruby_string "$license")
escaped_name=$(ruby_string "$name")

printf '# Supported: %s — other platforms: build from the checkout (README)\n' "$supported_platforms"
printf 'class %s < Formula\n' "$formula_class"
printf '  desc "%s"\n' "$escaped_description"
printf '  homepage "%s"\n' "$escaped_homepage"
printf '  version "%s"\n' "$(ruby_string "$version")"
printf '  license "%s"\n' "$escaped_license"
printf '\n'

index=0
while [ "$index" -lt "${#targets[@]}" ]; do
  url="https://github.com/${repo}/releases/download/v${version}/${asset_names[$index]}"
  printf '  on_%s do\n' "${os_blocks[$index]}"
  printf '    on_%s do\n' "${cpu_blocks[$index]}"
  printf '      url "%s"\n' "$(ruby_string "$url")"
  printf '      sha256 "%s"\n' "${checksums[$index]}"
  printf '    end\n'
  printf '  end\n'
  printf '\n'
  index=$((index + 1))
done

printf '%s\n' '  def install'
printf '    bin.install "%s"\n' "$escaped_name"
printf '%s\n' '  end'
printf '\n'

if [ -n "$caveats_file" ]; then
  printf '%s\n' '  def caveats'
  printf '%s\n' '    <<~EOS'
  while IFS= read -r caveat_line || [ -n "$caveat_line" ]; do
    escaped_caveat=$(ruby_string "$caveat_line")
    escaped_caveat=$(printf '%s' "$escaped_caveat" | sed 's/\${PREFIX}/#{HOMEBREW_PREFIX}/g')
    printf '      %s\n' "$escaped_caveat"
  done < "$caveats_file"
  printf '%s\n' '    EOS'
  printf '%s\n' '  end'
  printf '\n'
fi

printf '%s\n' '  test do'
printf '    assert_match version.to_s, shell_output("#{bin}/%s --version")\n' "$escaped_name"
printf '%s\n' '  end'
printf '%s\n' 'end'
