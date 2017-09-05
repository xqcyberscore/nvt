##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_information_disclosure_vuln.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# Open Ticket Request System (OTRS) Information Disclosure Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902361";
CPE = "cpe:/a:otrs:otrs";


if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7052 $");
  script_cve_id("CVE-2011-1433");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_name("Open Ticket Request System (OTRS) Information Disclosure Vulnerability");


tag_summary =
"This host is running Open Ticket Request System (OTRS) and is prone to
information disclosure vulnerability.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"The flaw is due to the error in 'AgentInterface' and 'CustomerInterface'
components, which place cleartext credentials into the session data in the
database.";

tag_impact =
"Successful exploitation will allow attackers to obtain sensitive information
by reading the _UserLogin and _UserPW fields.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version prior to 3.0.6";

tag_solution =
"Upgrade to Open Ticket Request System (OTRS) version 3.0.6 or later
For updates refer to http://otrs.org/download/";



  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "http://bugs.otrs.org/show_bug.cgi?id=6878");
  script_xref(name : "URL" , value : "http://source.otrs.org/viewvc.cgi/otrs/CHANGES?revision=1.1807");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
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
  if(version_is_less(version:vers, test_version:"3.0.6"))
  {
    security_message(port);
  }
}
