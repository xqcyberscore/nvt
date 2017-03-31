###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_mult_vuln_feb15.nasl 5190 2017-02-03 11:52:51Z cfi $
#
# Novell eDirectory iMonitor Multiple Vulnerabilities - Feb15
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

CPE = "cpe:/a:novell:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805269");
  script_version("$Revision: 5190 $");
  script_cve_id("CVE-2014-5212", "CVE-2014-5213");
  script_bugtraq_id(71741, 71748);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-03 12:52:51 +0100 (Fri, 03 Feb 2017) $");
  script_tag(name:"creation_date", value:"2015-02-06 12:01:38 +0530 (Fri, 06 Feb 2015)");
  script_name("Novell eDirectory iMonitor Multiple Vulnerabilities - Feb15");
  script_tag(name:"summary", value:"This host is installed with Novell eDirectory
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with
  the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple errors exists due to,
  - Improper sanitization by the /nds/search/data script when input is passed
    via the 'rdn' parameter.
  - An error in the /nds/files/opt/novell/eDirectory/lib64/ndsimon/public/images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server, and disclose virtual memory
  including passwords.

  Impact Level: Application");

  script_tag(name:"affected", value:"Novell eDirectory versions prior to 8.8 SP8
  Patch 4");

  script_tag(name:"solution", value:"Upgrade to Novell eDirectory version 8.8 SP8
  Patch 4 or later. For updates refer https://www.netiq.com");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/534284");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=3426981");
  script_summary("Check the version of Novell eDirectory is vulnerable or not");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("novell_edirectory_detect.nasl");
  script_mandatory_keys("eDirectory/installed");
  script_require_ports("Services/ldap", 389, 636);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
edirPort = "";
edirVer = "";

## get the port
if(!edirPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!edirVer = get_app_version(cpe:CPE, port:edirPort))
{
  exit(0);
}

##Get major version, service pack and patch versions
versions = eregmatch(string:edirVer, pattern:"^([0-9.]+)(.[A-Za-z0-9]+)?(.\(([0-9.]+)\))?");

##Get Major version
if(versions[1]){
  major = versions[1];
}

##Get Service pack, if any
if(versions[2]){
  sp = int(versions[2] - "SP");
}

##Get Patch version, if available
if(versions[4]){
  revision = versions[4];
}

if(major <= "8.8" && sp <= "8" && revision <= "20804.04")
{
  report = 'Installed version: ' + edirVer + '\n' +
           'Fixed version:     8.8 SP8 Patch4\n';
  security_message(data:report, port:edirPort);
  exit(0);
}
