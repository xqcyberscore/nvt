##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simpleid_xss_vuln.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# SimpleID 'index.php' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "SimpleID version prior to 0.6.5";

tag_insight = "Input passed via the 's' parameter to 'index.php' is not properly sanitised
  before being returned to the user.";
tag_solution = "Upgrade to SimpleID version 0.6.5 or later
  For updates refer to http://sourceforge.net/projects/simpleid/files/";
tag_summary = "This host is running SimpleID and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801416");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4972");
  script_name("SimpleID 'index.php' Cross Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simpleid_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
simidPort = get_http_port(default:80);
if(!get_port_state(simidPort)){
  exit(0);
}

## Get SimpleID version from KB
simidVer = get_version_from_kb(port:simidPort, app:"SimpleID/Ver");
if(simidVer != NULL)
{
  ## Check SimpleID version less than 0.6.5
  if(version_is_less(version: simidVer, test_version: "0.6.5")){
    security_message(simidPort);
  }
}
