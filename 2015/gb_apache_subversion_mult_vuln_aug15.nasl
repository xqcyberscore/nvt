###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_mult_vuln_aug15.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Apache Subversion Multiple Vulnerabilities - Aug15
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805095");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2015-3184", "CVE-2015-3187");
  script_bugtraq_id(76274, 76273);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-08-18 13:39:48 +0530 (Tue, 18 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Subversion Multiple Vulnerabilities - Aug15");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Flaws are due to,
  - The  mod_authz_svn does not properly restrict anonymous access in some
    mixed anonymous/authenticated environments when using Apache httpd 2.4.
  - The svnserve will reveal some paths  that should be hidden by path-based
    authz.  When a node is copied rom an unreadable location to a readable
    location the unreadable path may be revealed.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to obtain potentially sensitive information
  from an ostensibly hidden repository.

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Apache Subversion 1.7.x before 1.7.21 and 1.8.x before 1.8.14");

  script_tag(name:"solution", value:"Upgrade to version 1.7.21 or 1.8.14 or
  later, For updates refer https://subversion.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1033215");
  script_xref(name : "URL" , value : "http://subversion.apache.org/security/CVE-2015-3187-advisory.txt");
  script_xref(name : "URL" , value : "http://subversion.apache.org/security/CVE-2015-3184-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");
  script_require_ports("Services/www", 3690);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
http_port = 0;
subver = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

# Get Version
if(!subver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

#Checking for Vulnerable version
if(version_in_range(version:subver, test_version:"1.7.0", test_version2:"1.7.20"))
{
  fix = "1.7.21";
  VULN = TRUE;
}

if(version_in_range(version:subver, test_version:"1.8.0", test_version2:"1.8.13"))
{
  fix = "1.8.14";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + subver + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report, port:http_port);
  exit(0);
}
