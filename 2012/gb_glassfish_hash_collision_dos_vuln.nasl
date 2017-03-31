###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glassfish_hash_collision_dos_vuln.nasl 3045 2016-04-11 13:50:48Z benallard $
#
# Oracle GlassFish Server Hash Collision Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to cause a
denial of service via a specially crafted form sent in a HTTP POST request.

Impact Level: Application/System";

tag_affected = "Oracle GlassFish version 3.1.1 and prior.";

tag_insight = "The flaw is due to an error within a hash generation function
when hashing form posts and updating a hash table. This can be exploited to
cause a hash collision resulting in high CPU consumption via a specially
crafted form sent in a HTTP POST request.";

tag_solution = "Apply the updates from below link,
http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html";

tag_summary = "The host is running GlassFish Server and is prone to denial of
service vulnerability.";

if(description)
{
  script_id(802409);
  script_version("$Revision: 3045 $");
  script_cve_id("CVE-2011-5035");
  script_bugtraq_id(51194);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:50:48 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-01-05 16:15:38 +0530 (Thu, 05 Jan 2012)");
  script_name("Oracle GlassFish Server Hash Collision Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/903934");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2011-003.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the version of Oracle Java GlassFish Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("GlassFish_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));
if(!vers){
  exit(0);
}

if(version_is_less_equal(version: vers, test_version:"3.1.1")){
  security_message(port:port);
}
