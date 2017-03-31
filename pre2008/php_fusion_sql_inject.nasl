# OpenVAS Vulnerability Test
# $Id: php_fusion_sql_inject.nasl 3398 2016-05-30 07:58:00Z antu123 $
# Description: PHP-Fusion members.php SQL injection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 04/07/2009 Antu Sanadi <satnu@secpod.com> 
# Fixes by Tenable:
#   - added CVE and additional OSVDB xrefs.
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "Description :
  A vulnerability exists in the remote version of PHP-Fusion that may
  allow an attacker to inject arbitrary SQL code and possibly execute
  arbitrary code, due to improper validation of user supplied input in the
  'rowstart' parameter of script 'members.php'.";

tag_solution = "Upgrade to new verson.";

#  Ref: r0ut3r

if(description)
{
  script_id(15433);
  script_version("$Revision: 3398 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2437", "CVE-2004-2438");
  script_bugtraq_id(11296, 12425);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP-Fusion members.php SQL injection");
  script_summary( "Checks the version of the remote PHP-Fusion");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family( "Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
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

version = get_kb_item("www/" + port + "/php-fusion");
if(!version){
  exit(0);
}

if(version_is_less_equal(version:version,test_version:"4.0.1")){
  security_message(port);
}
