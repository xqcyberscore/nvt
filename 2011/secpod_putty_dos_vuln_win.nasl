###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_putty_dos_vuln_win.nasl 3114 2016-04-19 10:07:15Z benallard $
#
# Putty Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to cause denial of
service.

Impact Level: Application/System";

tag_affected = "Putty version 0.60";

tag_insight = "The flaw is caused to unspecified error in the application.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Putty and is prone to denial of
service vulnerability.";

if(description)
{
  script_id(902780);
  script_version("$Revision: 3114 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-26 18:52:49 +0530 (Mon, 26 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:07:15 +0200 (Tue, 19 Apr 2016) $");
  script_name("Putty Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18270/");
  script_xref(name : "URL" , value : "http://packetstorm.linuxsecurity.com/1112-exploits/putty060-dos.txt");

  script_summary("Check for Putty version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_putty_version.nasl");
  script_require_keys("SMB/WindowsVersion","PuTTY/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

## Get version from KB
puttyVer = get_kb_item("PuTTY/Version");
if(!puttyVer){
  exit(0);
}

## Check for putty version
if(version_is_equal(version:puttyVer, test_version:"0.60")){
  security_message(0);
}

