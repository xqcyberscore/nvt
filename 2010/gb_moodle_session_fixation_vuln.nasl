###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_session_fixation_vuln.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Moodle Session Fixation Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to conduct session
  fixation attacks.

  Impact level: System/Application";

tag_affected = "Moodle version 1.8.12 and prior
  Moodle version 1.9.x prior to 1.9.8";
tag_insight = "The flaws are exists due to:
  - failure to enable 'Regenerate session id during login', which can be
    exploited to conduct session fixation attacks.
  - creating new roles when restoring a course, which allows teachers to create
    new accounts if they do not have the 'moodle/user:create' capability.";
tag_solution = "Upgrade to latest version 1.9.8
  http://download.moodle.org/";
tag_summary = "This host is running Moodle and is prone to session fixation vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800767");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1613", "CVE-2010-1616");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Moodle Session Fixation Vulnerability");
  script_xref(name : "URL" , value : "http://moodle.org/security/");
  script_xref(name : "URL" , value : "http://tracker.moodle.org/browse/MDL-17207");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Moodle/Version");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

moodlePort = get_http_port(default:80);
if(!get_port_state(moodlePort)){
  exit(0);
}

# Get Moodle version from KB
moodleVer = get_kb_item("Moodle/Version");
if(!moodleVer){
  exit(0);
}

# Check for Moodle Version <= 1.8.12, < 1.9.8
if(version_in_range(version:moodleVer, test_version:"1.8",
   test_version2:"1.8.12") ||  version_in_range(version:moodleVer,
                      test_version:"1.9", test_version2:"1.9.7")){
  security_message(moodlePort);
}
