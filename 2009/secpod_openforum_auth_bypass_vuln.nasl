###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openforum_auth_bypass_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenForum 'profile.php' Authentication Bypass Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to bypass
security restrictions and modified user and password parameters.

Impact Level: Application";

tag_affected = "OpenForum version 0.66 Beta and prior.";

tag_insight = "The 'profile.php' script fails to restrict access to the admin
function which can be exploited via a direct request with the update parameter
set to 1.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with OpenForum and is prone to
Authentication Bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900927");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7066");
  script_bugtraq_id(32536);
  script_name("OpenForum 'profile.php' Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7291");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46969");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_openforum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

opnfrmPort = get_http_port(default:80);
if(!opnfrmPort){
  exit(0);
}

opnfrmVer = get_kb_item("www/" + opnfrmPort + "/OpenForum");
opnfrmVer = eregmatch(pattern:"^(.+) under (/.*)$", string:opnfrmVer);

if(opnfrmVer[1] != NULL)
{
  if(version_is_less_equal(version:opnfrmVer[1], test_version:"0.66.Beta")){
     security_message(opnfrmPort);
   }
}
