###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mahara_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mahara Multiple Remote Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site, steal cookie-based authentication credentials, disclose or modify
  sensitive information, or perform certain administrative actions and bypass
  security restrictions.
  Impact Level: Application";
tag_affected = "Mahara version prior to 1.3.6";
tag_insight = "- An error in artefact/plans/viewtasks.json.php, artefact/blog/posts.json.php,
    and blocktype/myfriends/myfriends.json.php when checking a user's permission
    can be exploited to access restricted views.
  - An error in view/newviewtoken.json.php, artefact/plans/tasks.json.php, and
    artefact/blog/view/index.json.php when checking a user's permission can be
    exploited to edit restricted views.
  - An error in admin/users/search.json.php due to the 'INSTITUTIONALADMIN'
    permission not being checked can be exploited to search and suspend other
    users.
  - The application allows users to perform certain actions via HTTP requests
    without performing any validity checks to verify the requests. This can be
    exploited to  create an arbitrary user with administrative privileges if a
    logged-in administrative user visits a malicious web site.
  - Input passed via certain email fields as a result of forum posts and view
    feedback notifications is not properly sanitised in artefact/comment/lib.php
    and interaction/forum/lib.php before being used.
  - Improper handling of an https URL in the wwwroot configuration setting,
    allows user-assisted remote attackers to obtain credentials by sniffing
    the network at a time when an http URL is used for a login.";
tag_solution = "Upgrade to Mahara version 1.3.6 or later.
  For updates refer to http://mahara.org/";
tag_summary = "This host is running Mahara and is prone to multiple remote
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801889");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_bugtraq_id(47798);
  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404",
                "CVE-2011-1405", "CVE-2011-1406");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mahara Multiple Remote Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44433");
  script_xref(name : "URL" , value : "https://launchpad.net/mahara/+milestone/1.3.6");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Mahara version from KB
if(vers = get_version_from_kb(port:port, app:"Mahara"))
{
  if(version_is_less(version: vers, test_version: "1.3.6")) {
    security_message(port:port);
  }
}
