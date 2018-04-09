###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k7_ultimate_security_privilege_escalation_vuln_feb15_win.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# K7 Ultimate Security Privilege Escalation Vulnerabilities Feb15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:k7computing:ultimate_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805453");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2014-9643");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("K7 Ultimate Security Privilege Escalation Vulnerabilities Feb15 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with K7 Ultimate
  Security and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to a write-what-where flaw
  in K7Sentry.sys in K7 Computing products that is triggered when handling
  certain IOCTL calls.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a local
  attacker to write controlled data to any memory location and execute code with
  kernel-level privileges.

  Impact Level: System");

  script_tag(name: "affected" , value:"K7 Ultimate Security before 14.2.0.253
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to K7 Ultimate Security version
  14.2.0.253 or later, For updates refer to http://www.k7computing.co.uk");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/35992");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/130246");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_k7_ultimate_security_detect_win.nasl");
  script_mandatory_keys("K7/UltimateSecurity/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
k7usecVer = "";
report = "";

## Get version
if(!k7usecVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:k7usecVer, test_version:"14.2.0.253"))
{
  report = 'Installed version: ' + k7usecVer + '\n' +
             'Fixed version:     ' + "14.2.0.253" + '\n';
  security_message(data:report );
  exit(0);
}
