###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_sec_bypass_vuln.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# McAfee ePolicy Orchestrator (ePO) Security Bypass Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803863";
CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6079 $");
  script_cve_id("CVE-2012-4594");
  script_bugtraq_id(55183);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-09 12:24:03 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Security Bypass Vulnerability");

 tag_summary =
"This host is running McAfee ePolicy Orchestrator and is prone to security
bypass vulnerability.";

  tag_vuldetect =
"Get the installed version with the help detect NVT and check the version is
vulnerable or not.";

  tag_insight =
"Flaw is due to an improper parsing of an ID value in a console URL.";

  tag_impact =
"Successful exploitation will allow remote authenticated attacker to gain
access to potentially sensitive information.";

  tag_affected =
"McAfee ePolicy Orchestrator (ePO) version 4.6.1 and earlier";

  tag_solution =
"According to vendor advisory, No remediation steps are required.
https://kc.mcafee.com/corporate/index?page=content&id=SB10025";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2012-4594");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10025");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vers = "";
port = 0;

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Get Symantec Web Gateway version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if(vers)
{
  if(version_is_less(version:vers, test_version:"4.6.1"))
  {
    security_message(port);
    exit(0);
  }
}
