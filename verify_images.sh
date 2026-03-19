#!/bin/bash

# Colors for output
export GREEN='\033[0;32m'
export RED='\033[91m'
export YELLOW='\033[1;33m'
export GRAY='\033[0;90m'
export BOLD='\033[1m'
export NC='\033[0m' # No Color
export ICON_OK='✔'
export ICON_FAIL='✗'
export ICON_INFO='●'

# Default values
MODE=""
TAG=""
NAMESPACE=""
CONTAINER_CMD=""
TAGFILE_ARG=""
VERBOSE="false"
URL_BASE="https://repo.metalsoft.io/release-hashes/"

# Function to display usage
usage() {
    echo "Usage: $0 [-t <tag>] [-f <file>] [-n <namespace>] [-k | -c] [-v]"
    echo "  -t <tag>        : Release tag (required unless -f is provided)"
    echo "  -f <file>       : Local tag file (overrides download)"
    echo "  -n <namespace>  : Kubernetes namespace (required for -k mode)"
    echo "  -k              : Verify running Kubernetes pods/deployments"
    echo "  -c              : Verify local container images (supports docker, ctr, podman, nerdctl, crictl)"
    echo "  -v              : Verbose output (show matched hash)"
    echo ""
    echo -e "url: ${BOLD}${URL_BASE}${TAG:-<tag>}${NC}"
    echo "Examples:"
    echo -e "  $0 -n ${BOLD}${ns:-namespace}${NC} -t ${BOLD}${TAG:-<tag>}${NC} -k"
    echo -e "  $0 -n ${BOLD}${ns:-namespace}${NC} -t ${BOLD}${TAG:-<tag>}${NC} -c"
    echo -e "  $0 -n ${BOLD}${ns:-namespace}${NC} -t ${BOLD}${TAG:-<tag>}${NC} -c -f ${BOLD}${TAG:-<tag>}${NC}"
    exit 1
}

# Parse command line arguments
while getopts "t:n:kchf:v" opt; do
    case $opt in
        t) TAG="$OPTARG" ;;
        f) TAGFILE_ARG="$OPTARG" ;;
        n) NAMESPACE="$OPTARG" ;;
        k) MODE="k8s" ;;
        c) MODE="container" ;;
        v) VERBOSE="true" ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$TAG" ] && [ -z "$TAGFILE_ARG" ]; then
    echo -e "${RED}Error: Tag (-t) or Tagfile (-f) is required.${NC}"
    usage
fi

if [ -z "$MODE" ]; then
    echo -e "${RED}Error: Mode (-k or -c) is required.${NC}"
    usage
fi

if [ "$MODE" == "k8s" ] && [ -z "$NAMESPACE" ]; then
    # Fallback to env var if not provided via flag
    if [ -n "$ns" ]; then
        NAMESPACE="$ns"
    else
        echo -e "${RED}Error: Namespace (-n) is required for Kubernetes mode.${NC}"
        usage
    fi
fi

# Pre-flight dependency checks
preflight_checks() {
    local errors=()
    local warnings=()

    # Bash version (export -f, [[ ]], process substitution require bash 3+)
    if [ -z "${BASH_VERSINFO+x}" ] || [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
        errors+=("Bash version 3+ required (found: ${BASH_VERSION:-not bash})")
    fi

    # Core POSIX utilities used throughout the script
    local required_utils=("awk" "sed" "grep" "sort" "mktemp" "xargs" "head")
    for util in "${required_utils[@]}"; do
        if ! command -v "$util" &>/dev/null; then
            errors+=("Required utility '$util' not found in PATH")
        fi
    done

    # xargs -P parallel support (non-fatal -- script still works sequentially)
    if command -v xargs &>/dev/null; then
        if ! echo "test" | xargs -P 1 echo &>/dev/null; then
            warnings+=("xargs does not support -P (parallel) flag; verification will run sequentially")
        fi
    fi

    # kubectl availability and cluster connectivity (k8s mode only)
    if [ "$MODE" == "k8s" ]; then
        if ! command -v kubectl &>/dev/null; then
            errors+=("kubectl not found in PATH (required for -k mode)")
        else
            if ! kubectl cluster-info --request-timeout=5s &>/dev/null; then
                errors+=("kubectl cannot connect to cluster (check kubeconfig / cluster availability)")
            elif ! kubectl get ns "$NAMESPACE" --request-timeout=5s &>/dev/null; then
                errors+=("Namespace '$NAMESPACE' not found in cluster")
            fi
        fi
    fi

    # Write permissions: CWD must be writable when downloading tag file
    if [ -z "$TAGFILE_ARG" ]; then
        if ! touch .verify_images_preflight_test 2>/dev/null; then
            errors+=("Current directory is not writable (needed to download tag file)")
        else
            rm -f .verify_images_preflight_test
        fi
    fi

    # Temp directory creation (used for parallel result aggregation)
    local test_tmp
    if test_tmp=$(mktemp -d 2>/dev/null); then
        rmdir "$test_tmp"
    else
        errors+=("Cannot create temporary directories (check /tmp permissions)")
    fi

    for warn in "${warnings[@]}"; do
        echo -e "${YELLOW}[PREFLIGHT] $warn${NC}"
    done

    if [ ${#errors[@]} -gt 0 ]; then
        for err in "${errors[@]}"; do
            echo -e "${RED}[PREFLIGHT] $err${NC}"
        done
        exit 1
    fi

}

preflight_checks

# Detect container runtime for container mode or deep k8s verification
if [ "$MODE" == "container" ] || [ "$MODE" == "k8s" ]; then
    if command -v docker &>/dev/null; then
        CONTAINER_CMD="docker"
    elif command -v ctr &>/dev/null; then
        CONTAINER_CMD="ctr"
    elif command -v podman &>/dev/null; then
        CONTAINER_CMD="podman"
    elif command -v nerdctl &>/dev/null; then
        CONTAINER_CMD="nerdctl"
    elif command -v crictl &>/dev/null; then
        CONTAINER_CMD="crictl"
    else
        if [ "$MODE" == "container" ]; then
            echo -e "${RED}Error: No supported container runtime found (docker, ctr, podman, nerdctl, crictl).${NC}"
            exit 1
        fi
        # For k8s mode, it's optional but useful for deep verification
        CONTAINER_CMD=""
    fi
    if [ -n "$CONTAINER_CMD" ]; then
         echo -e "${GRAY}${ICON_INFO}${NC} Using container runtime: ${BOLD}$CONTAINER_CMD${NC}"
    fi
fi

# Export variables for parallel execution
export MODE NAMESPACE CONTAINER_CMD VERBOSE GRAY ICON_OK ICON_FAIL ICON_INFO

# Determine tag file source
if [ -n "$TAGFILE_ARG" ]; then
    tagfile="$TAGFILE_ARG"
    if [ ! -f "$tagfile" ]; then
         echo -e "${RED}Error: Specified tag file '$tagfile' not found.${NC}"
         exit 1
    fi
    echo -e "${GRAY}${ICON_INFO}${NC} Using local tag file: ${BOLD}$tagfile${NC}"
else
    tagfile="${TAG}.txt"
    url="${URL_BASE}${TAG}.txt"
    echo -ne "${GRAY}${ICON_INFO}${NC} Downloading release hashes for tag: $TAG..."
    if command -v curl &>/dev/null; then
        curl_err=$(mktemp)
        curl -sSf "$url" -o "${tagfile}" 2>"$curl_err"
        curl_exit=$?
        if [ $curl_exit -ne 0 ]; then
            echo -e " ${RED}${ICON_FAIL}${NC}"
            cat "$curl_err" 2>/dev/null
            rm -f "$curl_err"
            echo -e "${RED}Error: Could not download $url using curl${NC}"
            echo "Curl exit code: $curl_exit"
            if [ $curl_exit -eq 22 ]; then
                echo "  (HTTP Error, likely 404 Not Found)"
            fi
            rm -f "${tagfile}"
            exit 3
        fi
    elif command -v wget &>/dev/null; then
        wget_err=$(mktemp)
        wget -q "$url" -O "${tagfile}" 2>"$wget_err"
        wget_exit=$?
        if [ $wget_exit -ne 0 ]; then
            echo -e " ${RED}${ICON_FAIL}${NC}"
            cat "$wget_err" 2>/dev/null
            rm -f "$wget_err"
            echo -e "${RED}Error: Could not download $url using wget${NC}"
            echo "Wget exit code: $wget_exit"
            rm -f "${tagfile}"
            exit 3
        fi
    else
        echo -e " ${RED}${ICON_FAIL}${NC}"
        echo -e "${RED}Error: Neither curl nor wget found. Cannot download tag file.${NC}"
        exit 1
    fi

    # Sanity check: Ensure downloaded file is not HTML (e.g. 404 page that wasn't caught by exit code)
    if grep -qEi "^\s*<(!DOCTYPE|html)" "$tagfile"; then
        echo -e " ${RED}${ICON_FAIL}${NC}"
        echo -e "${RED}Error: Downloaded file appears to be HTML (likely a 404 page or error page).${NC}"
        echo "Content preview:"
        head -n 5 "$tagfile"
        rm -f "${tagfile}"
        exit 3
    fi
    echo -e " ${GREEN}${ICON_OK}${NC}"
fi

echo -e "${GRAY}${ICON_INFO}${NC} Verifying images (Mode: ${BOLD}$MODE${NC})"
if [ "$MODE" == "k8s" ]; then
    echo -e "${GRAY}${ICON_INFO}${NC} Namespace: ${BOLD}$NAMESPACE${NC}"
fi
echo "---------------------------------------------------"

# Sort tagfile
sort "$tagfile" > "${tagfile}.sorted"

# Create temp directory for parallel results
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT
export TMP_DIR

# Sanitize hash values from tag file (strip trailing non-hex chars)
# shellcheck disable=SC2329
sanitize_hash() {
    echo "$1" | sed -E 's/[^a-fA-F0-9:]+$//'
}
export -f sanitize_hash

# Define the worker function
# shellcheck disable=SC2329
verify_deployment() {
    local line="$1"
    local deployment_name=$(echo "$line" | awk '{print $1}')
    local expected_hash=$(sanitize_hash "$(echo "$line" | awk '{print $2}')")
    local matched_hash=""
    
    # Skip empty lines or comments
    [[ -z "$deployment_name" || "$deployment_name" =~ ^# ]] && return 0

    # Determine search terms for this deployment (used for both K8s and Container mode logic)
    local search_terms=("$deployment_name")
    case "$deployment_name" in
        "ai-monitoring-agent"|"ai-mcp-server"|"ai-infra-assistant") search_terms+=("ai-agent") ;;
        "bsi-pdns") search_terms+=("pdns") ;;
        "ui-consumer") search_terms+=("ui-customer") ;;
        "ui-customer") search_terms+=("ui-consumer") ;;
    esac
    if [[ "$deployment_name" == *"-microservice" ]]; then
        search_terms+=("${deployment_name%-microservice}")
    fi

    if [ "$MODE" == "k8s" ]; then
        # Kubernetes Verification Logic
        
        # Check if deployment exists
        local actual_deployment_name="$deployment_name"

        # Specific overrides for known discrepancies
        case "$deployment_name" in
            "ai-monitoring-agent"|"ai-mcp-server"|"ai-infra-assistant") actual_deployment_name="ai-agent" ;;
            "bsi-pdns") actual_deployment_name="pdns" ;;
            "ui-consumer") actual_deployment_name="ui-customer" ;;
        esac
        
        if ! kubectl -n "$NAMESPACE" get deploy "$actual_deployment_name" &>/dev/null; then
            # Try appending -microservice
            if kubectl -n "$NAMESPACE" get deploy "${deployment_name}-microservice" &>/dev/null; then
                 actual_deployment_name="${deployment_name}-microservice"
            # Try removing -microservice suffix
            elif [[ "$deployment_name" == *"-microservice" ]] && kubectl -n "$NAMESPACE" get deploy "${deployment_name%-microservice}" &>/dev/null; then
                 actual_deployment_name="${deployment_name%-microservice}"
            else
                echo -e "${YELLOW}${ICON_INFO}${NC} $deployment_name ${GRAY}(not deployed in namespace '$NAMESPACE' - skipped)${NC}"
                return 0
            fi
        fi

        # Get selector using go-template for reliability (outputs key=value,key=value)
        local selector=$(kubectl -n "$NAMESPACE" get deploy "$actual_deployment_name" -o go-template='{{range $k,$v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}' | sed 's/,$//')

        if [ -z "$selector" ]; then
            echo -e "${RED}${ICON_FAIL}${NC} Could not determine selector for '$actual_deployment_name'"
            return 1
        fi

        # Determine container name for filtering
        local container_name="$actual_deployment_name"
        case "$deployment_name" in
            "ai-monitoring-agent") container_name="monitoring-agent" ;;
            "ai-mcp-server") container_name="mcp-server" ;;
            "ai-infra-assistant") container_name="infra-assistant" ;;
            "bsi-pdns") container_name="bsi-pdns" ;;
        esac

        # Get running image IDs from all containers in pods matching the selector, including container name
        local pod_data=$(kubectl -n "$NAMESPACE" get pods --selector="$selector" -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.name}{"\t"}{.imageID}{"\n"}{end}{end}')

        if [ -z "$pod_data" ]; then
            echo -e "${RED}${ICON_FAIL}${NC} No running pods found for '$actual_deployment_name'"
            return 1
        fi

        # Filter for the specific container if possible
        local running_image_ids=$(echo "$pod_data" | grep "^${container_name}"$'\t' | awk '{print $2}' | sort -u)
        
        # If filter returned nothing (container name mismatch?), fall back to all images
        if [ -z "$running_image_ids" ]; then
             running_image_ids=$(echo "$pod_data" | awk '{print $2}' | sort -u)
        fi

        # Check if the expected hash is present in the running image IDs
        if echo "$running_image_ids" | grep -q "$expected_hash"; then
             matched_hash=$(echo "$running_image_ids" | grep "$expected_hash" | sed '/^[[:space:]]*$/d' | head -n 1)
             [ -z "$matched_hash" ] && matched_hash="$expected_hash"
             # Standardize output: Just the name if it matches exactly, or with clarification if name changed
             if [ "$deployment_name" == "$actual_deployment_name" ]; then
                if [ "$VERBOSE" == "true" ]; then
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name ${BOLD}$matched_hash${NC}"
                else
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name"
                fi
             else
                if [ "$VERBOSE" == "true" ]; then
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $actual_deployment_name) ${BOLD}$matched_hash${NC}"
                else
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $actual_deployment_name)"
                fi
             fi
             return 0
        else
            # Deep Check: Resolve running image ID to manifest digest when possible (containerd/docker)
            local match_found=false
            local resolved_digests=""

            if [ -n "$CONTAINER_CMD" ]; then
                for running_id in $running_image_ids; do
                    # Strip prefix if present (e.g. docker-pullable://) to get pure hash or sha256:hash
                    local clean_id=$(echo "$running_id" | sed 's/^.*sha256:/sha256:/')

                    if [ "$CONTAINER_CMD" == "ctr" ]; then
                         # ctr images list outputs: REF TYPE DIGEST SIZE PLATFORMS LABELS
                         # When REF is the imageID, DIGEST is the manifest digest
                         local digest=$(ctr images list 2>/dev/null | awk -v ref="$clean_id" '$1==ref {print $3}')
                         if [ -z "$digest" ]; then
                             digest=$(ctr -n k8s.io images list 2>/dev/null | awk -v ref="$clean_id" '$1==ref {print $3}')
                         fi
                         if [ -n "$digest" ]; then
                             resolved_digests+="$digest"$'\n'
                             if [ "$digest" == "$expected_hash" ]; then
                                 match_found=true
                                 matched_hash="$digest"
                             fi
                         fi
                    elif [ "$CONTAINER_CMD" == "docker" ]; then
                         # Check if running ID (Config Digest) maps to expected RepoDigest
                         if docker images --digests --no-trunc | grep "$clean_id" | grep -q "$expected_hash"; then
                             match_found=true
                             matched_hash="$expected_hash"
                         fi
                    fi
                done
            fi

            if [ "$match_found" == "true" ]; then
                 [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                 if [ "$deployment_name" == "$actual_deployment_name" ]; then
                    if [ "$VERBOSE" == "true" ]; then
                        echo -e "${GREEN}${ICON_OK}${NC} $deployment_name ${BOLD}$matched_hash${NC}"
                    else
                        echo -e "${GREEN}${ICON_OK}${NC} $deployment_name"
                    fi
                 else
                    if [ "$VERBOSE" == "true" ]; then
                        echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $actual_deployment_name) ${BOLD}$matched_hash${NC}"
                    else
                        echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $actual_deployment_name)"
                    fi
                 fi
                 return 0
            else
                local deploy_image=""
                deploy_image=$(kubectl -n "$NAMESPACE" get deploy "$actual_deployment_name" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\t"}{.image}{"\n"}{end}' 2>/dev/null | awk -v c="$container_name" '$1==c {print $2; exit}')
                local image_tag=""
                if [ -n "$deploy_image" ]; then
                    local ref_without_digest="${deploy_image%%@*}"
                    if [[ "$ref_without_digest" == *:* ]]; then
                        image_tag="${ref_without_digest##*:}"
                    fi
                fi
                [ -z "$image_tag" ] && image_tag="${TAG:-<none>}"
                echo -e "${RED}${ICON_FAIL}${NC} $deployment_name (found as $actual_deployment_name) ${YELLOW}image tag: ${image_tag}${NC}"
                echo -e "  ${GRAY}${ICON_INFO}${NC} Expected: ${BOLD}$expected_hash${NC}"
                if [ -n "$resolved_digests" ]; then
                    echo -e "  ${GRAY}${ICON_INFO}${NC} Found (Resolved manifest digest):"
                    echo -e "${BOLD}$(echo "$resolved_digests" | sort -u | sed '/^[[:space:]]*$/d' | sed 's/^/            /')${NC}"
                else
                    echo -e "  ${GRAY}${ICON_INFO}${NC} Found (K8s reported imageID):"
                    echo -e "${BOLD}$(echo "$running_image_ids" | sed '/^[[:space:]]*$/d' | sed 's/^/            /')${NC}"
                fi
                return 1
            fi
        fi

    elif [ "$MODE" == "container" ]; then
        # Local Container Verification Logic
        
        local found_images="false"
        local matched_name=""
        
        # Helper to check if a line contains any of the search terms
        check_line_match() {
            local line="$1"
            for term in "${search_terms[@]}"; do
                if [[ "$line" == *"$term"* ]]; then
                    matched_name="$term"
                    return 0
                fi
            done
            return 1
        }
        
        # Search strategy depends on runtime
        if [ "$CONTAINER_CMD" == "docker" ] || [ "$CONTAINER_CMD" == "podman" ] || [ "$CONTAINER_CMD" == "nerdctl" ]; then
             # Get all lines matching hash
             while read -r line; do
                 if check_line_match "$line"; then
                     found_images="true"
                     matched_hash=$(echo "$line" | awk '{print $2}')
                     [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                     break
                 fi
             done < <($CONTAINER_CMD images --digests --format "{{.Repository}}:{{.Tag}} {{.Digest}} {{.ID}}" | grep "$expected_hash")
             
             if [ "$found_images" == "false" ]; then
                 while read -r line; do
                     if check_line_match "$line"; then
                         found_images="true"
                         matched_hash=$(echo "$line" | awk '{print $2}')
                         [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                         break
                     fi
                 done < <($CONTAINER_CMD images --no-trunc --format "{{.Repository}}:{{.Tag}} {{.ID}}" | grep "$expected_hash")
             fi
            
        elif [ "$CONTAINER_CMD" == "ctr" ]; then
            # ctr output: REF TYPE DIGEST ...
            while read -r line; do
                 if check_line_match "$line"; then
                     found_images="true"
                     matched_hash=$(echo "$line" | awk '{print $3}')
                     [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                     break
                 fi
            done < <(ctr images list | grep "$expected_hash")
            
            if [ "$found_images" == "false" ]; then
                while read -r line; do
                     if check_line_match "$line"; then
                         found_images="true"
                         matched_hash=$(echo "$line" | awk '{print $3}')
                         [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                         break
                     fi
                done < <(ctr -n k8s.io images list 2>/dev/null | grep "$expected_hash")
            fi
            
        elif [ "$CONTAINER_CMD" == "crictl" ]; then
             while read -r line; do
                 if check_line_match "$line"; then
                     found_images="true"
                     matched_hash=$(echo "$line" | awk '{print $2}')
                     [ -z "$matched_hash" ] && matched_hash="$expected_hash"
                     break
                 fi
             done < <(crictl images -v | grep "$expected_hash")
        fi

        if [ "$found_images" == "true" ]; then
            [ -z "$matched_hash" ] && matched_hash="$expected_hash"
            # Standardize output to match K8s mode
            if [ -n "$matched_name" ] && [ "$matched_name" != "$deployment_name" ]; then
                if [ "$VERBOSE" == "true" ]; then
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $matched_name) ${BOLD}$matched_hash${NC}"
                else
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name (found as $matched_name)"
                fi
            else
                if [ "$VERBOSE" == "true" ]; then
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name ${BOLD}$matched_hash${NC}"
                else
                    echo -e "${GREEN}${ICON_OK}${NC} $deployment_name"
                fi
            fi
            return 0
        else
            # Try to find candidates by name to report what we HAVE instead of just "MISSING"
            local candidates=""
            
            for term in "${search_terms[@]}"; do
                if [ "$CONTAINER_CMD" == "ctr" ]; then
                    # Grep for term in the image ref
                    local found=$(ctr images list 2>/dev/null | grep "$term" | awk '{print $3}')
                    if [ -z "$found" ]; then
                         found=$(ctr -n k8s.io images list 2>/dev/null | grep "$term" | awk '{print $3}')
                    fi
                    if [ -n "$found" ]; then
                        candidates+="$found"$'\n'
                    fi
                elif [ "$CONTAINER_CMD" == "docker" ] || [ "$CONTAINER_CMD" == "podman" ] || [ "$CONTAINER_CMD" == "nerdctl" ]; then
                     local found=$($CONTAINER_CMD images --digests --format "{{.Repository}}:{{.Tag}} {{.Digest}}" | grep "$term" | awk '{print $2}')
                     if [ -n "$found" ]; then
                        candidates+="$found"$'\n'
                     fi
                fi
            done
            
            if [ -n "$candidates" ]; then
                echo -e "${RED}${ICON_FAIL}${NC} $deployment_name"
                echo -e "  ${GRAY}${ICON_INFO}${NC} Expected: ${BOLD}$expected_hash${NC}"
                echo -e "  ${GRAY}${ICON_INFO}${NC} Found (Local candidates):"
                echo -e "${BOLD}$(echo "$candidates" | sort | uniq | sed '/^[[:space:]]*$/d' | sed 's/^/            /')${NC}"
            else
                echo -e "${RED}${ICON_FAIL}${NC} $deployment_name"
                echo -e "  ${GRAY}${ICON_INFO}${NC} Expected Hash: ${BOLD}$expected_hash${NC}"
                echo -e "  ${GRAY}${ICON_INFO}${NC} Status: Not found in local registry ($CONTAINER_CMD)"
            fi
            return 1
        fi
    fi
    return 0
}
export -f verify_deployment

# Wrapper to capture output and exit code
# shellcheck disable=SC2329
process_line() {
    local line="$1"
    local deployment_name=$(echo "$line" | awk '{print $1}')
    [[ -z "$deployment_name" || "$deployment_name" =~ ^# ]] && return 0
    
    verify_deployment "$line" > "$TMP_DIR/${deployment_name}.log" 2>&1
    echo $? > "$TMP_DIR/${deployment_name}.exit"
}
export -f process_line

# Run parallel checks
# Use xargs to run in parallel. We pass the line as argument.
cat "${tagfile}.sorted" | xargs -P 10 -I {} bash -c 'process_line "$@"' _ {}

# Aggregate results
mismatches=0
total=0

while read -r deployment_name expected_hash; do
    # Skip empty lines or comments
    [[ -z "$deployment_name" || "$deployment_name" =~ ^# ]] && continue
    
    ((total++))
    
    if [ -f "$TMP_DIR/${deployment_name}.log" ]; then
        cat "$TMP_DIR/${deployment_name}.log"
    fi
    
    if [ -f "$TMP_DIR/${deployment_name}.exit" ]; then
        code=$(cat "$TMP_DIR/${deployment_name}.exit")
        if [ "$code" -ne 0 ]; then
            ((mismatches++))
        fi
    else
        # Should not happen if xargs runs correctly
        echo -e "${RED}Error: Failed to process $deployment_name${NC}"
        ((mismatches++))
    fi
    
done < "${tagfile}.sorted"

echo "---------------------------------------------------"
if [ "$mismatches" -eq 0 ]; then
    echo -e "${GREEN}All $total checks passed successfully.${NC}"
    exit 0
else
    echo -e "${RED}Found $mismatches mismatches (or missing items) out of $total checked.${NC}"
    exit 1
fi

