###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_mult_bof_vuln.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Advantech WebAccess Multiple Stack Based Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:advantech:advantech_webaccess";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804478");
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-0985", "CVE-2014-0986", "CVE-2014-0987", "CVE-2014-0988",
                "CVE-2014-0989", "CVE-2014-0990", "CVE-2014-0991", "CVE-2014-0992");
  script_bugtraq_id(69529, 69531, 69532, 69533, 69534, 69535, 69536, 69538);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-08 12:07:35 +0530 (Mon, 08 Sep 2014)");

  script_name("Advantech WebAccess Multiple Stack Based Buffer Overflow Vulnerabilities");

  script_tag(name: "summary" , value:"This host is running Advantech WebAccess
  and is prone to multiple stack based buffer overflow vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version of
  Advantech WebAccess with the help of detect NVT and check the version
  is vulnerable or not.");

  script_tag(name: "insight" , value: "The multiple stack based buffer
  overflow flaws are due to an error when parsing NodeName, GotoCmd,
  NodeName2, AccessCode, AccessCode2, UserName, projectname, password
  parameters");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  attackers execution of arbitrary code within the context of the
  application, or otherwise crash the whole application.

  Impact Level: System/Application");

  script_tag(name: "affected" , value: "Advantech WebAccess before 7.3");

  script_tag(name: "solution" , value: "Upgrade to Advantech
  WebAccess 7.2 or later, For updates refer to http://webaccess.advantech.com");

  script_xref(name: "URL" , value: "http://www.coresecurity.com/advisories/advantech-webaccess-vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_advantech_webaccess_detect.nasl");
  script_mandatory_keys("Advantech/WebAccess/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
awPort = "";
awVer = "";

## Get Application HTTP Port
if(!awPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get application version
awVer = get_app_version(cpe:CPE, port:awPort);
if(!awVer){
  exit(0);
}

if(version_is_less(version:awVer, test_version:"7.3"))
{
  security_message(port:awPort);
  exit(0);
}
