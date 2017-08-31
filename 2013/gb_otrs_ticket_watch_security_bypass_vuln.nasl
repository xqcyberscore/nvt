###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_ticket_watch_security_bypass_vuln.nasl 6755 2017-07-18 12:55:56Z cfischer $
#
# OTRS Ticket Watch Security Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803943";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6755 $");
  script_cve_id("CVE-2013-4088");
  script_bugtraq_id(60688);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 14:55:56 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-09-22 10:18:31 +0530 (Sun, 22 Sep 2013)");
  script_name("OTRS Ticket Watch Security Bypass Vulnerability");

tag_summary =
"This host is installed with OTRS (Open Ticket Request System) and is prone to
security bypass vulnerability.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"An error exists in application which fails properly verifying permissions
when accessing tickets via the ticket watch mechanism";

tag_impact =
"Successful exploitation will allow remote authenticated users to bypass
intended security restriction and obtain sensitive information.

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version 3.0.x up to and including 3.0.20,
3.1.x up to and including 3.1.16 and 3.2.x up to and including 3.2.7.";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 3.0.21 or 3.1.17 or
3.2.8 or later, For updates refer to http://www.otrs.com/en/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/60688");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53851/");
  script_xref(name : "URL" , value : "http://www.otrs.com/en/open-source/community-news/security-advisories/Security-Advisory-2013-04/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

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
  if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.7") ||
     version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.20") ||
     version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.16"))
  {
      security_message(port:port);
      exit(0);
  }

}
