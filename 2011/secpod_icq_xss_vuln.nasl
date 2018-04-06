###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_icq_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ICQ Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_insight = "The flaw is due to lack of input validation and output
sanitisation of the profile entries.

Impact
Successful exploitation will allow remote attackers to hijack session IDs of
users and leverage the vulnerability to increase the attack vector to the
underlying software and operating system of the victim.

Impact Level: Application.

Affected Software:
ICQ version 7.5 and prior.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with ICQ and is prone to cross-site
scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902702");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ICQ Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103430/icqcli-xss.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_icq_detect.nasl");
  script_require_keys("ICQ/Ver");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

## Get the version from KB
icqVer = get_kb_item("ICQ/Ver");
if(!icqVer){
  exit(0);
}

## Check for ICQ version less than or equal to 7.5
if(version_is_less_equal(version:icqVer, test_version:"7.5.0.5255")){
  security_message(0);
}
