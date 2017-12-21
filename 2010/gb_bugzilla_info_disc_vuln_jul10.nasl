###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_info_disc_vuln_jul10.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Bugzilla 'Install/Filesystem.pm' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to read sensitive
  configuration fields.
  Impact Level: Application";
tag_affected = "Bugzilla version 3.5.1 to 3.6.1 and 3.7 through 3.7.1,";
tag_insight = "The flaw is due to an error in 'install/Filesystem.pm', which uses
  world-readable permissions within 'bzr/' and 'data/webdot/'.";
tag_solution = "upgrade Bugzilla 3.7.2 or later,
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "This host is running Bugzilla and is prone to information disclosure
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801368");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2470");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Bugzilla 'Install/Filesystem.pm' Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.bugzilla.org/status/changes.html");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=561797");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

vers = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!vers){
 exit(0);
}

if(version_in_range(version:vers, test_version:"3.7", test_version2:"3.7.1") ||
   version_in_range(version:vers, test_version:"3.5.1", test_version2:"3.6.1")){
  security_message(port:port);
}
