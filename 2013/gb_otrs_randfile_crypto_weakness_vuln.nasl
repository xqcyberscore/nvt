###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_randfile_crypto_weakness_vuln.nasl 6755 2017-07-18 12:55:56Z cfischer $
#
# OTRS RANDFILE Cryptographic Entropy Weakness Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803921";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6755 $");
  script_cve_id("CVE-2009-5057");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 14:55:56 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-09-21 20:18:31 +0530 (Sat, 21 Sep 2013)");
  script_name("OTRS RANDFILE Cryptographic Entropy Weakness Vulnerability");


tag_summary =
"This host is installed with OTRS (Open Ticket Request System) and is prone to
cryptographic entropy weakness vulnerability.";

tag_vuldetect ="Get the installed version of OTRS with the help of detect NVT
and check the version is vulnerable or not.";

tag_insight =
"An error exists in S/MIME feature which does not configure the RANDFILE and
HOME environment variables for OpenSSL";

tag_impact =
"Successful exploitation will allow attackers to decrypt e-mail messages.

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version before 2.3.4";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 2.3.4 or later,
For updates refer to http://www.otrs.com/en/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_is_less(version: vers, test_version: "2.3.4"))
  {
      security_message(port:port);
      exit(0);
  }

}
