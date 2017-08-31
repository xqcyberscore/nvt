###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_mult_vuln_apr14.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Vtiger CRM Multiple Vulnerabilities April-14
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vtiger:vtiger_crm";
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.802070";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-2268", "CVE-2014-2269");
  script_bugtraq_id(66757, 66758);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-16 16:28:47 +0530 (Wed, 16 Apr 2014)");
  script_name("Vtiger CRM Multiple Vulnerabilities April-14");

tag_summary =
"This host is installed with Vtiger CRM and is prone to multiple
vulnerabilities";

tag_vuldetect =
"Send a crafted HTTP GET request and check whether it responds with error
message.";

tag_insight =
"- No access control or restriction is enforced when the changePassword()
function in 'forgotPassword.php' script is called.
- Flaw in the install module that is triggered as input passed via the
'db_name' parameter is not properly sanitized.";

tag_impact =
"Successful exploitation will allow remote attackers to change the password
of any user or remote attackers can execute arbitrary php code.

Impact Level: System/Application";

tag_affected =
"Vtiger CRM version 6.0.0 (including Security Patch1), 6.0 RC, 6.0 Beta.";

tag_solution =
"Apply Security Patch 2 for Vtiger 6.0 (issued on March 16, 2014),
For patch refer to, http://sourceforge.net/projects/vtigercrm/files/vtiger%20CRM%206.0.0/Add-ons";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32794");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126067");
  script_xref(name : "URL" , value : "https://www.navixia.com/blog/entry/navixia-find-critical-vulnerabilities-in-vtiger-crm-cve-2014-2268-cve-2014-2269.html");
  script_xref(name : "URL" , value : "http://vtiger-crm.2324883.n4.nabble.com/Vtigercrm-developers-IMP-forgot-password-and-re-installation-security-fix-tt9786.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/installed");
  script_require_ports("Services/www", 80, 8888);
  exit(0);
}


include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";
res = "";
req = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Vtiger Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct random user
rand_username = "userdoesnotexists" +
                rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:7);

## Construct the attack request with userdoesnotexists
url = dir + string('/modules/Users/actions/ForgotPassword.php?username=',
      rand_username,'&password=admin&confirmPassword=admin');

req = http_get(item:url, port:http_port);
res = http_keepalive_send_recv( port:http_port, data:req, bodyonly:FALSE);

## Patched version replay with specific message
if ("200 OK" >< res && "index.php?module=Users&action=Login" >< res &&
    ">Loading .... <" >< res && "please retry setting the password" >!< res){
  security_message(port:http_port);
}
