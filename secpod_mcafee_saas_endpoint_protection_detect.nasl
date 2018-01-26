###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_saas_endpoint_protection_detect.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# McAfee SaaS Endpoint Protection Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script finds the installed McAfee SaaS Endpoint Protection
  version and saves the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902561");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("McAfee SaaS Endpoint Protection Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902561";
SCRIPT_DESC = "McAfee SaaS Endpoint Protection Version Detection (Windows)";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application
key = "SOFTWARE\McAfee\ManagedServices\Agent";
if(!registry_key_exists(key:key)) {
  exit(0);
}

name = registry_get_sz(key:key, item:"szAppName");
if("McAfee Security-as-a-Service" >< name)
{
  ## Get Version
  version = registry_get_sz(key:key, item:"szMyAsUtilVersion");
  if(version)
  {
    ## Set McAfee SaaS Endpoint Protection Version in KB
    set_kb_item(name:"McAfee/SaaS/Win/Ver", value:version);
    log_message(data:"McAfee SaaS Endpoint Protection " + version +
                       " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:saas_endpoint_protection:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
