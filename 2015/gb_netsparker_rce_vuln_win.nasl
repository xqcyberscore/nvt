###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsparker_rce_vuln_win.nasl 6229 2017-05-29 09:04:10Z teissa $
#
# Netsparker Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:netsparker:wass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805961");
  script_version("$Revision: 6229 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-29 11:04:10 +0200 (Mon, 29 May 2017) $");
  script_tag(name:"creation_date", value:"2015-08-24 11:47:10 +0530 (Mon, 24 Aug 2015)");
  script_name("Netsparker Remote Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Netsparker and
  is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient validation
  of input passed to the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code on the affected system.

  Impact Level: System/Application.");

  script_tag(name:"affected", value:"Netsparker versions 2.3.x on Windows.");

  script_tag(name:"solution", value:"No solution or patch was made available for
  at least one year since disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/37746");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_netsparker_detect_win.nasl");
  script_mandatory_keys("Netsparker/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
netVer = "";


## Get version
if(!netVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(netVer =~ "^(2\.3\.)")
{
  report = 'Installed version: ' + netVer + '\n' +
           'Fixed version:     ' + "Not Available" + '\n';
  security_message(data:report );
  exit(0);
}
