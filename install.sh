#!/bin/bash

function usage {
  script=$(basename "$0")
  cat << EOF
${script} - Setup csutil components in your Cluster.
USAGE:
    ${script} -c=<CLUSTER_NAME_OR_ID> --crn-service-name=<CRN_SERVICE_NAME> --crn-cname=<CRN_CNAME> --sos-config-path=<OPENVPN_FILE_PATH>

WHERE,
REQUIRED:
    -c, --cluster      : cluster-name or cluster-id where you want to install csutil.
    --crn-service-name : application/service-name that is registered while SOS Onboarding.
    --crn-cname        : dev/prestage/staging/prod/internal
    --sos-config-path  : path to openvpn file provided by SOS team. [Not required if sos-vpn-secret already exists]

OPTIONAL:
    --dlc                     : Set true to encrypt the logs through DLC(Disconnected Logs Component) and forward it to QRADAR. [Bydefault false]
    --kube-config-ctx         : Pass the desired kube-context to run this script.
    --nessus-private          : Set false to deploy nessus-proxy and use vpn-connection instead. [Bydefault true]
    --nessus-pre-ga           : Set true to utilize early versions of healthchecks used by nessus. [Bydefault false]
    --uptycs                  : Set false to opt out of uptycs on worker nodes. [By default true]
    -h, --help                : Show help.

EXAMPLES:
  ${script} -c=c9kgcph20h3u5i1v0sig --crn-service-name=servicename --crn-cname=dev --sos-config-path=/path/servicename0001.ovpn
  ${script} -c=ca2tvk020fa3kiiot6t0 --crn-service-name=servicename --crn-cname=staging --sos-config-path=/path/servicename0001.ovpn
  ${script} -c=caso8u720moe76fp3sj0 --crn-service-name=servicename --crn-cname=prod --sos-config-path=/path/servicename0001.ovpn
  ${script} -c=c9kgc4720igbgcndi76g --crn-service-name=servicename --crn-cname=internal --sos-config-path=/path/servicename0001.ovpn
  ${script} -c=ca2tvk020fa3kiiot6t0 --crn-service-name=servicename --crn-cname=prod --sos-config-path=/path/servicename0001.ovpn --dlc=true
  ${script} -c=ca2tvk020fa3kiiot6t0 --crn-service-name=servicename --crn-cname=prod --sos-config-path=/path/servicename0001.ovpn --dlc=true --uptycs=false
EOF
}


RED='\033[1;91m' # Bold Red Color
NC='\033[0m' # No Color
GREEN='\033[1;32m'
BLUE='\033[1;36m'
WHITE='\033[1;37m'

function print_failed {
  printf "\n"
  printf "%bFAILED%b\n" "${RED}" "${NC}"
}


function print_success {
  printf "\n"
  printf "%bINSTALLATION COMPLETE.%b\n" "${GREEN}" "${NC}"
}


function print_summary {
  printf "%bINSTALLATION SUMMARY:%b\n" "${BLUE}" "${NC}"
  printf "Add-on %b%s%b is enabled in the cluster %b%s%b now.\n" "${BLUE}" "${ADDON_NAME}" "${NC}" "${BLUE}" "${CLUSTER_NAME_OR_ID}" "${NC}"
  INSTALLED_VERSION=$(kubectl get cm -n ibm-services-system csutil-images -o json | jq -r '.metadata.annotations.version') || true
  printf "${WHITE}INSTALLED_VERSION:${NC} ${BLUE}%s${NC}\n" "${INSTALLED_VERSION}"
  printf "However, it may take time to update the Addon status as %bAddon Ready%b. Please refer to below %bCHECK HEALTH-STATUS%b section for more.\n" "${WHITE}" "${NC}" "${WHITE}" "${NC}"

}

function check_status {
  printf "%bCHECK HEALTH-STATUS:%b\n" "${BLUE}" "${NC}"
  printf "PODs may take upto 15 to 20 mins to be in a Running state. When all mandatory PODS are Running that indicates the VPN connectivity is established and reports are successfully being published.\n"
  printf "\n"
  printf "Once PODs are Running, Please wait for atleast 10 to 15 mins before checking for Health Status of the add-on.\n"
  printf "$ ibmcloud ks cluster addon ls -c %s\n" "${CLUSTER_NAME_OR_ID}"
  printf "%bnormal%b indicates that all expected pods are in Running state, You're all Set!!!\n" "${WHITE}" "${NC}"
  printf "\n"
  printf "%bcritical%b indicates that some add-on components are unhealthy. You can check for not Running pods using,\n" "${WHITE}" "${NC}"
  printf "$ kubectl get all -n ibm-services-system -o wide\n"
  printf "For any other Health State,Please refer https://cloud.ibm.com/docs/containers?topic=containers-managed-addons#debug_addons_review"
  printf "\n"
}


function additional_info {
  printf "%bADDITIONAL INFO:%b\n" "${BLUE}" "${NC}"
  printf "You can check current running patch version of csutil using,\n"
  printf "$ kubectl get cm -n ibm-services-system csutil-images -o jsonpath='{.metadata.annotations.version}'\n"
  printf "\n"
  printf "Also, You can check the list of images and image-tags used in csutil from csutil-images configmap.\n"
  printf "$ kubectl get cm -n ibm-services-system csutil-images -o yaml\n"
}

# Exit for help.
[[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] || [[ "$1" == "" ]] && usage && exit 1


CLUSTER_NAME_OR_ID_FLAG=""
CRN_SERVICE_NAME_FLAG=""
CRN_CNAME_FLAG=""
KUBE_CONFIG_CTX_FLAG=""
VPN_FILE_PATH_FLAG=""

DLC=""
NESSUS_PRIVATE=""
NESSUS_PRE_GA=""


for i in "$@"; do
  case ${i} in
    -c=*|--cluster=*)
      CLUSTER_NAME_OR_ID_FLAG=${i%%=*}
      CLUSTER_NAME_OR_ID="${i#*=}"
      if [[ "${CLUSTER_NAME_OR_ID}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${CLUSTER_NAME_OR_ID_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${CLUSTER_NAME_OR_ID_FLAG}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -crnservicename=*|--crn-service-name=*)
      CRN_SERVICE_NAME_FLAG=${i%%=*}
      CRN_SERVICE_NAME="${i#*=}"
      if [[ "${CRN_SERVICE_NAME}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${CRN_SERVICE_NAME_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${CRN_SERVICE_NAME_FLAG}"
        exit 1
      fi
      if [[ "${CRN_SERVICE_NAME}" =~ [^a-z0-9-] ]]; then
        printf "%b service-name MUST be unique globally and MUST be alphanumeric, lower case, no spaces or special characters other than '-'%b" "${RED}" "${NC}" && exit 1
      fi
      shift # past argument=value
      ;;
    -crncname=*|--crn-cname=*)
      CRN_CNAME_FLAG=${i%%=*}
      CRN_CNAME=${i#*=}
      if [[ "${CRN_CNAME}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${CRN_CNAME_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${CRN_CNAME_FLAG}"
        exit 1
      fi
      CRN_CNAME_LOWER=$(echo "${CRN_CNAME}" | tr '[:upper:]' '[:lower:]')
      # if [[ ! ( "${CRN_CNAME_LOWER}" == *"staging"* || "${CRN_CNAME_LOWER}" == *"bluemix"* || "${CRN_CNAME_LOWER}" == *"dev"* || "${CRN_CNAME_LOWER}" == *"stage"* || "${CRN_CNAME_LOWER}" == *"prod"* ) ]]; then
      #   printf "${RED}cname value %s is not valid, It should contain dev/stage/prod in the name${NC}" "${CRN_CNAME}" && exit 1
      # fi
      shift # past argument=value
      ;;
    -kube-config-ctx=*|--kube-config-ctx=*)
      KUBE_CONFIG_CTX_FLAG=${i%%=*}
      KUBE_CONFIG_CTX=${i#*=}
      if [[ "${KUBE_CONFIG_CTX}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${KUBE_CONFIG_CTX_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${KUBE_CONFIG_CTX_FLAG}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -sosconfigpath=*|--sos-config-path=*)
      VPN_FILE_PATH_FLAG=${i%%=*}
      VPN_FILE_PATH="${i#*=}"
      if [[ ${VPN_FILE_PATH} == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${VPN_FILE_PATH_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${VPN_FILE_PATH_FLAG}"
        exit 1
      elif [[ "${VPN_FILE_PATH}" != *".ovpn" ]]; then
        print_failed
        printf "Path %s is not valid. Please pass a file having valid extension either ${WHITE}.ovpn${NC} or ${WHITE}.tar${NC}\n" "${VPN_FILE_PATH}" && usage
        exit 1
      fi
      shift # past argument=value
      ;;
    -addon-name=*|--addon-name=*)
      ADDON_NAME_INPUT="${i#*=}"
      if [[ ${ADDON_NAME_INPUT} == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${i%%=*}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${i%%=*}"
        exit 1
      elif [[ ! ( "${ADDON_NAME_INPUT}" == "csutil" || "${ADDON_NAME_INPUT}" == "csutil-experimental" ) ]]; then
        usage
        print_failed
        printf "%s=%s is not valid. Please pass csutil or csutil-experimental in %s.\n" "${i%%=*}" "${ADDON_NAME_INPUT}" "${i%%=*}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -dlc=*|--dlc=*)
      DLC="${i#*=}"
      if [[ "${DLC}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${i%%=*}" && usage
        print_failed
        printf "flag needs an argument : ${WHITE}%s${NC}\n" "${i%%=*}"
        exit 1
      elif [[ ! ( "${DLC}" == "true" || "${DLC}" == "false" ) ]]; then
        usage
        print_failed
        printf "%s=%s is not valid. Please pass true or false in %s.\n" "${i%%=*}" "${DLC}" "${i%%=*}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -nessusprivate=*|--nessus-private=*)
      NESSUS_PRIVATE="${i#*=}"
      if [[ "${NESSUS_PRIVATE}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${i%%=*}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${i%%=*}"
        exit 1
      elif [[ ! ( "${NESSUS_PRIVATE}" == "true" || "${NESSUS_PRIVATE}" == "false" ) ]]; then
        usage
        print_failed
        printf "%s=%s is not valid. Please pass true or false in %s.\n" "${i%%=*}" "${NESSUS_PRIVATE}" "${i%%=*}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -nessusprega=*|--nessus-pre-ga=*)
      NESSUS_PRE_GA="${i#*=}"
      if [[ "${NESSUS_PRE_GA}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${i%%=*}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${i%%=*}"
        exit 1
      elif [[ ! ( "${NESSUS_PRE_GA}" == "true" || "${NESSUS_PRE_GA}" == "false" ) ]]; then
        usage
        print_failed
        printf "%s=%s is not valid. Please pass true or false in %s.\n" "${i%%=*}" "${NESSUS_PRE_GA}" "${i%%=*}"
        exit 1
      fi
      shift # past argument=value
      ;;
    -uptycs=*|--uptycs=*)
      UPTYCS_FLAG=${i%%=*}
      UPTYCS="${i#*=}"
      if [[ "${UPTYCS}" == "" ]]; then
        printf "Incorrect Usage: flag needs an argument : %s\n" "${UPTYCS_FLAG}" && usage
        print_failed
        printf "${WHITE}flag needs an argument : ${RED}%s${NC}\n" "${UPTYCS_FLAG}"
        exit 1
      elif [[ ! ( "${UPTYCS}" == "true" || "${UPTYCS}" == "false" ) ]]; then
        usage
        print_failed
        printf "%s=%s is not valid. Please pass true or false in %s.\n" "${UPTYCS_FLAG}" "${UPTYCS}" "${UPTYCS_FLAG}"
        exit 1
      fi
      shift # past argument=value
      ;;
    --default)
      export DEFAULT=YES
      shift # past argument with no value
      ;;
    *)
      # unknown option
      ;;
  esac
done


# Check if mandatory flags are passed in input or not.
FLAGS_MISSING=""
if [[ ! ( "${CLUSTER_NAME_OR_ID_FLAG}" == "-c" || "${CLUSTER_NAME_OR_ID_FLAG}" == "--cluster" ) ]]; then
  FLAGS_MISSING="${FLAGS_MISSING}-c, "
fi

if [[ ! ( "${CRN_SERVICE_NAME_FLAG}" == "-crnservicename" || "${CRN_SERVICE_NAME_FLAG}" == "--crn-service-name" ) ]]; then
  FLAGS_MISSING="${FLAGS_MISSING}--crn-service-name, "
fi

if [[ ! ( "${CRN_CNAME_FLAG}" == "-crncname" || "${CRN_CNAME_FLAG}" == "--crn-cname" ) ]]; then
  FLAGS_MISSING="${FLAGS_MISSING}--crn-cname, "
fi

if [[ "${FLAGS_MISSING}" != "" ]]; then
    printf "Incorrect Usage: flag %s mandatory; but missing from input\n" "${FLAGS_MISSING}" && usage
    print_failed
    printf "flag %s mandatory; but missing from input.\n" "${FLAGS_MISSING}"
    exit 1
fi

# Check if user logged in to correct ibmcloud account or not.
printf "\n"
printf "<-----Checking ibmcloud login....----->\n"
IS_LOGGEDIN=$(ibmcloud iam oauth-tokens)
if [[ ${IS_LOGGEDIN} == "" ]]; then
  printf "%bPlease login to account first.%b\n" "${RED}" "${NC}"
  exit 1
else
  printf "User is currently LoggedIn to account.\n"
  printf "%bOK%b" "${GREEN}" "${NC}"
fi

printf "\n"
CLUSTER_DETAILS=$(ibmcloud ks cluster get --cluster "${CLUSTER_NAME_OR_ID}" --output json)
if [[ ${CLUSTER_DETAILS} == "" ]]; then
  print_failed
  printf "Please check if cluster %b%s%b exists under this account or not.\n" "${GREEN}" "${CLUSTER_NAME_OR_ID}" "${NC}"
  exit 2
fi

# Get crn values of cluster.
CRN=$(echo "${CLUSTER_DETAILS}" | jq -r '.crn') || true
# CRN_BASE=$(echo "$CRN"| cut -d ':' -f 1,2,3,4) # ex.: crn:v1:staging:public
CRN_CRN=$(echo "${CRN}"| cut -d ':' -f 1)
CRN_VERSION=$(echo "${CRN}"| cut -d ':' -f 2)
export CRN_CNAME="${CRN_CNAME}"
CRN_CTYPE=$(echo "${CRN}"| cut -d ':' -f 4)
export CRN_BASE
CRN_BASE=$(echo "${CRN_CRN}:${CRN_VERSION}:${CRN_CNAME}:${CRN_CTYPE}:${CRN_SERVICE_NAME}") # ex.: crn:v1:staging:public:crn-service-name

CRN_REGION=$(echo "${CLUSTER_DETAILS}" | jq -r '.region') || true
ACCOUNT_ID=$(echo "${CRN}"| cut -d ':' -f 7)
ACCOUNT_ID_=${ACCOUNT_ID/\//_}                           # replacing '/' with '_' in account-id.
CLUSTER_ID=$(echo "${CRN}"| cut -d ':' -f 8)
CLUSTER_NAME=$(echo "${CLUSTER_DETAILS}" | jq -r '.name') || true
CLUSTER_TYPE=$(echo "${CLUSTER_DETAILS}" | jq -r '.type') || true

PROVIDER=$(echo "${CLUSTER_DETAILS}" | jq -r '.provider') || true

# Setup kubectl Context.
printf "\n"
if [[ "${KUBE_CONFIG_CTX}" == "" ]]; then
  printf "<-----Setting kubectl context for %s....----->\n" "${CLUSTER_NAME_OR_ID}"
  if [[ "${PROVIDER}" == "satellite" ]]; then
    ibmcloud ks cluster config --cluster "${CLUSTER_NAME_OR_ID}" --admin --endpoint link
  else
    ibmcloud ks cluster config --cluster "${CLUSTER_NAME_OR_ID}" --admin
  fi

  CONTEXT_SUCCESS=$?
  if [[ ${CONTEXT_SUCCESS} -ne 0 ]]; then
    printf "Error while setting context to %s.\n" "${CLUSTER_NAME_OR_ID}"
    exit 1
  fi
else
  printf "<-----Switching to context %s....----->\n" "${KUBE_CONFIG_CTX}"
  kubectl config use-context "${KUBE_CONFIG_CTX}"
  SWITCH_CONTEXT=$?
  if [[ ${SWITCH_CONTEXT} -ne 0 ]]; then
    printf "Error while Switching context to %s.\n" "${KUBE_CONFIG_CTX}"
    exit 1
  fi
fi

OS_TYPE=$(kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.osImage' | awk '{print $1}') || true

SOS_OWNER_EMAIL=$(ibmcloud target --output json | jq -r '.user.user_email') || true
# if SOS_OWNER_EMAIL is empty, set a temp value.
if [[ "${SOS_OWNER_EMAIL}" == "" ]]; then
  SOS_OWNER_EMAIL="replace_with_eamil"
fi

# Creating ibm-services-system namespace and required configmaps.
printf "\n"
printf "<-----Creating ibm-services-system namespace and required configmaps....----->\n"
cat <<-EOF | kubectl apply -f - 2>&1 | grep -i -v "Warn" | grep -i -v "Deprecat"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: ibm-services-system
      labels:
        name: ibm-services-system
        pod-security.kubernetes.io/enforce: privileged
        pod-security.kubernetes.io/enforce-version: latest
        pod-security.kubernetes.io/audit: privileged
        pod-security.kubernetes.io/audit-version: latest
        pod-security.kubernetes.io/warn: privileged
        pod-security.kubernetes.io/warn-version: latest
  - apiVersion: v1
    kind: ConfigMap
    data:
      CLUSTER_NAME: ${CLUSTER_NAME}
      CRN_BASE: ${CRN_BASE}
      CRN_CNAME: ${CRN_CNAME}                      # staging/bluemix/custom_value
      CRN_CTYPE: ${CRN_CTYPE}                      # public/dedicated/local
      CRN_REGION: ${CRN_REGION}                    # cluster-region
      CRN_SCOPE: ${ACCOUNT_ID}                     # ibmcloud account-id
      CRN_SCOPE_: ${ACCOUNT_ID_}
      CRN_VERSION: v1
      CRN_RESOURCE_TYPE: worker
      CRN_SERVICE_NAME: ${CRN_SERVICE_NAME}        # crn-service-name
      CRN_SERVICE_INSTANCE: ${CLUSTER_ID}          # cluster-id
      SOS_ADMIN_W3ID: ${SOS_OWNER_EMAIL}           # sos-owner email
      SOS_OPERATOR_USAM_SYSTEM: NONE
      C_CODE: ARMADA
      BUSINESS_UNIT: BU203
      BUSINESS_UNIT_SMALL: bu203
    metadata:
      name: crn-info-services
      namespace: ibm-services-system
  - apiVersion: v1
    kind: ConfigMap
    data:
      dlcTestDestPort: "32502"
      dlcProdDestPort: "32500"
      dlcListenPort: "6514"
      dlcMicroservicesListenPort: "7514"
      dlcProxyListenPort: "32500"
      dlcMicroservicesProxyListenPort: "32501"
      fimProxyPort: "443"
      kubeauditlogForwarderexternalPort: "8080"
      NESSUS_HOST: "iksnm1.sos.ibm.com"
      NESSUS_PORT: "8834"
      sosW10ProxyListenPort: "1443"
      sosW10ProxyDestPort: "443"
      sosW10Endpoint: "10.142.84.23"
      syslogForwarderPort: "10514"
      SOS_BUSINESS_UNIT: "BU203"
      SOS_EPS_PORT: "514"
      dlcProxyStageDestHostname: "siem04s02-dlcsp-lb.sos.ibm.com"
      dlcProxyProdDestHostname: "siem04s01-dlcp-lb.sos.ibm.com"
      dlcMicroservicesProxyStageDestHostname: "siem04s02-dlcsp-lb.sos.ibm.com"
      dlcMicroservicesProxyProdDestHostname: "siem04s01-dlcp-lb.sos.ibm.com"
      READINESS_TEST_IP: "10.143.108.65"
      SOS_EPS_FQDN: "10.142.84.30"
      SOS_EPS_FQDN_STAGING: "10.142.84.31" # staging
    metadata:
      name: csutil-ports
      namespace: ibm-services-system
EOF

CM_CREATED=$?
if [[ ${CM_CREATED} -ne 0 ]]; then
  printf "Aborting as error occured while creating the required configmaps.\n"
  exit 1
fi

cat <<-EOF | kubectl apply -f - 2>&1 | grep -i -v "Warn" | grep -i -v "Deprecat"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    data:
      # Refer to the below section from README to change the default CPU and memory settings for any Csutil container.
      # https://github.ibm.com/ibmcloud/ArmadaCSutil#system-requirements-table
    metadata:
      name: csutil-cpu-memory
      namespace: ibm-services-system
EOF

CM_MEM_CPU_CREATED=$?
if [[ ${CM_MEM_CPU_CREATED} -ne 0 ]]; then
  printf "Aborting as error occured while creating the required configmaps.\n"
  exit 1
else
  printf "%bOK%b" "${GREEN}" "${NC}"
  printf "\n"
fi

if [[ "${CLUSTER_TYPE}" == "kubernetes" ]]; then
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"IKS": "true"}}' > /dev/null 2>&1
else
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/IKS"}]' > /dev/null 2>&1
fi

if [[ "${OS_TYPE}" == "Red" ]]; then
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"RHEL": "true"}}' > /dev/null 2>&1
else
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/RHEL"}]' > /dev/null 2>&1
fi

if [[ "${CRN_CNAME_LOWER}" == "staging" ]]; then
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"STAGING": "true"}}' > /dev/null 2>&1
else
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/STAGING"}]' > /dev/null 2>&1
fi

if [[ "${UPTYCS}" == "false" ]]; then
  printf "\n"
  printf "<-----Flag --uptycs=false. Disabling Uptycs from the cluster.....----->\n"
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"UPTYCS_DISABLED": "true"}}' > /dev/null 2>&1
  printf "Uptycs is disabled in the cluster now.\n"
else
  printf "\n"
  printf "<-----Flag --uptycs is not false. Hence, ensuring uptycs is not disabled from the cluster....----->\n"
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/UPTYCS_DISABLED"}]' > /dev/null 2>&1
  printf "Uptycs is enabled in the cluster now.\n"
fi

if [[ "${DLC}" == "true" ]]; then
  printf "\n"
  printf "<-----Flag --dlc=true. Enabling DLC in the cluster.....----->\n"
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"DLC_ENABLED": "true"}}' > /dev/null 2>&1
  printf "DLC is enabled in the cluster now.\n"
fi

if [[ "${DLC}" == "false" ]]; then
  printf "\n"
  printf "<-----Flag --dlc=false. Hence, Disabling DLC from the cluster.....----->\n"
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/DLC_ENABLED"}]' > /dev/null 2>&1
  printf "DLC is disabled from the cluster now."
fi

if [[ "${NESSUS_PRIVATE}" == "false" ]]; then
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"NESSUS_PRIVATE": "false"}}' > /dev/null 2>&1
fi

# Patch pre-ga group in sos-nessus-agent daemonset.
if [[ "${NESSUS_PRE_GA}" == "true" ]]; then
  kubectl patch configmap -n ibm-services-system crn-info-services --type=merge -p '{"data": {"NESSUS_PRE_GA": "true"}}' > /dev/null 2>&1
fi

# if .ovpn file passed, re-create the sos-vpn-secret.
if [[ "${VPN_FILE_PATH}" != "" ]]; then
  # if --sos-config-path is passed, delete old secret, create new secret and restart the sos-tools pod(if exists).
  printf "\n"
  printf "<-----Creating sos-vpn-secret from a given ovpn file....----->\n"
  kubectl delete secret sos-vpn-secret -n ibm-services-system --ignore-not-found > /dev/null 2>&1
  kubectl create secret generic sos-vpn-secret -n ibm-services-system --from-file="${VPN_FILE_PATH}"
  SECRET_CREATED=$?
  if [[ ${SECRET_CREATED} -ne 0 ]]; then
    printf "Error while creating sos-vpn-secret.\n"
    exit 1
  fi
  kubectl rollout restart -n ibm-services-system deployment/sos-tools --ignore-not-found > /dev/null 2>&1
fi

# Checking for sos-vpn-secret existence in the cluster.
printf "\n"
printf "<-----Checking for sos-vpn-secret existence in the cluster....----->\n"
SOS_VPN_SECRET_EXISTS=$(kubectl get secret --namespace ibm-services-system sos-vpn-secret --no-headers --ignore-not-found | wc -l) || true
if [[ ${SOS_VPN_SECRET_EXISTS} -eq 1 ]]; then
  # if secret exists, no need to create it.
  printf "sos-vpn-secret exists under ibm-services-system namespace.\n"
else
  printf "sos-vpn-secret doesn't exist in the cluster.\n"
  if [[ "${VPN_FILE_PATH}" == "" ]]; then
    printf "Incorrect Usage: flag --sos-config-path required, but missing from input\n" && usage
    print_failed
    printf "flag --sos-config-path required as sos-vpn-secret doesn't exist under ibm-services-system namespace.\n"
    exit 1
  fi
  printf "\n"
fi

# If openshift, apply privileged SCC.
if [[ "${CLUSTER_TYPE}" == "openshift" ]]; then
  # check for oc cli installation.
  if ! command oc &> /dev/null
  then
    printf "\n"
    printf "OpenShift CLI (oc) could not be found. This is required for csutil installation on OpenShift clusters.\n"
    exit 1
  fi
  oc adm policy add-scc-to-user privileged system:serviceaccount:ibm-services-system:default > /dev/null 2>&1
  oc adm policy add-scc-to-user privileged system:serviceaccount:ibm-services-system:nessus-agent > /dev/null 2>&1
fi

# Enabling csutil add-on, if not enabled already.
ADDON_NAME=""
printf "\n"
printf "<-----Checking if add-on is already enabled or not. If not, then enabling it....----->\n"
ENABLED=$(ibmcloud ks cluster addon ls -c "${CLUSTER_NAME_OR_ID}" | grep -c 'csutil') || true
if [[ ${ENABLED} -eq 2 ]]; then
  ADDON_NAME_1=$(ibmcloud ks cluster addon ls -c "${CLUSTER_NAME_OR_ID}" | grep 'csutil'| head -n 1 | awk '{print $1}') || true
  ADDON_NAME_2=$(ibmcloud ks cluster addon ls -c "${CLUSTER_NAME_OR_ID}" | grep 'csutil'| tail -n 1 | awk '{print $1}') || true
  printf "%s and %s both are enabled, Please disable one of them using below command, then re-run this script again.\n" "${ADDON_NAME_1}" "${ADDON_NAME_2}"
  printf "ibmcloud ks cluster addon disable <ADDON_NAME> -c <CLUSTER_NAME_OR_ID>\n"
  exit 1
elif [[ ${ENABLED} -eq 1 ]]; then
  ADDON_NAME=$(ibmcloud ks cluster addon ls -c ${CLUSTER_NAME_OR_ID} --output json | jq '.[]|select( .name | startswith("csutil")) | .name') || true
  printf "%s add-on is already enabled.\n" "${ADDON_NAME}"
else
  if [[ "${ADDON_NAME_INPUT}" != "" ]]; then
    ADDON_NAME=${ADDON_NAME_INPUT}
  else
    # if crn-cname (when converted to lower case) starts with stag, dev or pre, default to experimental, else not.
    if [[ "${CRN_CNAME_LOWER}" == "stag"* || "${CRN_CNAME_LOWER}" == "dev"* || "${CRN_CNAME_LOWER}" == "pre"* ]]; then
      ADDON_NAME="csutil-experimental"
    else
      ADDON_NAME="csutil"
    fi
  fi
  ibmcloud ks cluster addon enable "${ADDON_NAME}" --cluster "${CLUSTER_NAME_OR_ID}"
  ADDON_ENABLE=$?
  if [[ ${ADDON_ENABLE} -ne 0 ]]; then
    printf "Aborted as there is an error while enabling the %s add-on.\n" "${ADDON_NAME}"
    exit 1
  fi
fi


# Wait for 22 mins to make sure that all yaml resources applied in the cluster.
DEPLOY_SUCCESS=0
DEPLOY_SUCCESS=$(kubectl get deploy -n ibm-services-system sos-tools --no-headers --ignore-not-found| wc -l) || true
if [[ ${DEPLOY_SUCCESS} -eq 0 ]]; then
  printf "\n"
  printf "<-----Waiting for the add-on resources to get fully deployed. This might take around 5 to 20 minutes....----->\n"
  ATTEMPTS=0
  ATTEMPT_NO=0
  DEPLOY_SUCCESS=$(kubectl get deploy -n ibm-services-system sos-tools --no-headers --ignore-not-found| wc -l) || true
  if [[ ${DEPLOY_SUCCESS} -eq 0 ]]; then
    # Initially sleep for 15 secs.
    sleep 5
  fi

  while [[ ${ATTEMPTS} -lt 132 ]]; do
    DEPLOY_SUCCESS=$(kubectl get deploy -n ibm-services-system sos-tools --no-headers --ignore-not-found| wc -l) || true
    if [[ ${DEPLOY_SUCCESS} -ne 0 ]]; then
      break
    fi
    ATTEMPTS=$((ATTEMPTS+1))
    if [[ $(( ATTEMPTS % 6 )) == 1 ]]; then
      ATTEMPT_NO=$((ATTEMPT_NO+1))
      printf "Attempt %s: Waiting for 60s...\n" "${ATTEMPT_NO}"
    fi
    # refreshing login token every 5 minutes.
    if [[ $(( ATTEMPT_NO % 5 )) == 0 ]]; then
      ibmcloud iam oauth-tokens > /dev/null 2>&1
    fi
    sleep 10
  done

  if [[ ${ATTEMPTS} -eq 132 ]]; then
    printf "Add-on is not fully deployed yet. Please re-run this script after 30 mins.\n"
    exit 1
  else
    printf "Add-on deployed successfully.\n"
  fi
fi


# Waiting for kube-auditlog-forwarder service to come in a Running state.
printf "\n"
printf "<-----Waiting for kube-auditlog-forwarder service to come in a Running state....----->\n"
SERVICE_CREATED=$(kubectl get services --namespace ibm-services-system kube-auditlog-forwarder --no-headers --ignore-not-found | wc -l) || true
if [[ ${SERVICE_CREATED} -ne 1 ]]; then
  printf "kube-auditlog-forwarder service is not Running...Please configure webhook later using below script.\n"
  printf "https://github.ibm.com/ibmcloud/ArmadaCSutil/blob/master/setuphook.sh"
  printf "\n"
else
  printf "kube-auditlog-forwarder service is Running now.\n"
  export AUDIT_URL="https://127.0.0.1:2040/api/v1/namespaces/ibm-services-system/services/kube-auditlog-forwarder/proxy/post"
  if ! ibmcloud ks cluster ca get -c "$CLUSTER_NAME_OR_ID" --output json | jq '.caCert' --raw-output | base64 -d >> "$(pwd)"/"$CLUSTER_NAME_OR_ID".pem; then
    print_failed
    printf "Failed to obtain and decode the Cluster CA Cert\n"
    exit 2
  fi
  CA_CERT=$(pwd)/$CLUSTER_NAME_OR_ID.pem

  export CA_CERT AUDIT_URL

  printf "\n"
  printf "<-----Setting Kubernetes API server audit-webhook....----->\n"

  CLIENT_CERT=$(kubectl config view --minify -o jsonpath='{.users[0].user.client-certificate}') || true

  if [[ "$CLIENT_CERT" == "" ]]; then
    # Fallback to client-certificate-data
    kubectl config view --minify --raw --output jsonpath='{.users[0].user.client-certificate-data}' | base64 -d > client.crt

    if [ -s client.crt ]; then
      CLIENT_CERT=$(readlink -f client.crt)
    fi
  fi

  if [[ "${CLIENT_CERT}" == "" ]]; then
    print_failed
    printf "client-certificate is empty (client-certificate-data too), but it is required for audit-webhook setup.\n"
  fi

  CLIENT_KEY=$(kubectl config view --minify -o jsonpath='{.users[0].user.client-key}')

  if [[ "$CLIENT_KEY" == "" ]]; then
    # Fallback to client-key-data
    kubectl config view --minify --raw --output jsonpath='{.users[0].user.client-key-data}' | base64 -d > client.key

    if [ -s client.key ]; then
      CLIENT_KEY=$(readlink -f client.key)
    fi
  fi

  if [[ "${CLIENT_KEY}" == "" ]]; then
    print_failed
    printf "client-key is empty (client-key-data too). that is required for audit-webhook setup.\n"
    rm ${CA_CERT}
    exit 1
  fi

  export AUDIT_PARAMETERS="--ca-cert ${CA_CERT} --client-cert ${CLIENT_CERT} --client-key ${CLIENT_KEY}"
  ibmcloud ks cluster master audit-webhook set --cluster ${CLUSTER_NAME_OR_ID} --remote-server ${AUDIT_URL} ${AUDIT_PARAMETERS}
  SET_WEBHOOK=$?
  if [[ ${SET_WEBHOOK} -ne 0 ]]; then
    printf "FAILED as there is an error while setting up apiserver webhook.\n"
    rm ${CA_CERT}
    exit 1
  fi

  ibmcloud ks cluster master refresh --cluster ${CLUSTER_NAME_OR_ID}
  MASTER_REFRESH=$?
  if [[ ${MASTER_REFRESH} -ne 0 ]]; then
    printf "FAILED as there is an error while refershing an apiserver after webhook setup.\n"
    rm ${CA_CERT}
    exit 1
  fi

  ibmcloud ks cluster master audit-webhook get --cluster ${CLUSTER_NAME_OR_ID}
  rm ${CA_CERT}
  printf "audit logs should flow now.\n"
fi

# Patch required Proxy variables in sos-nessus-agent daemonset.
if [[ "${NESSUS_PRIVATE}" == "false" ]]; then
  # Adding required env variables in sos-nessus-agent daemonset.
  kubectl patch -n ibm-services-system daemonset sos-nessus-agent -p '{"spec":{"template":{"spec":{"containers": [{"env":[{"name":"PROXY_SERVER","value":"$(NESSUS_PROXY_SERVICE_SERVICE_HOST)"}, {"name":"PROXY_PORT","value":"3128"}],"name":"sos-nessus-agent"}]}}}}' > /dev/null 2>&1
  printf "\n"
  printf "nessus-proxy configured in the cluster now.\n"
else
  # remove PROXY_SERVER and PROXY_PORT env vars from sos-nessus-agent daemonset.
  kubectl patch -n ibm-services-system daemonset sos-nessus-agent -p '{"spec": {"template": {"spec": {"containers": [{"name": "sos-nessus-agent", "env": [{"$patch": "delete", "name": "PROXY_SERVER"}, {"$patch": "delete", "name": "PROXY_PORT"}],"name":"sos-nessus-agent"}]}}}}' > /dev/null 2>&1
  kubectl patch configmap -n ibm-services-system crn-info-services --type=json -p='[{"op": "remove", "path": "/data/NESSUS_PRIVATE"}]' > /dev/null 2>&1
fi

print_success
printf "\n"

print_summary
printf "\n"

check_status
printf "\n"

additional_info
printf "\n"
exit 0
