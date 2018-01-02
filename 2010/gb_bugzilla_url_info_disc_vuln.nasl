###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_url_info_disc_vuln.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# Bugzilla URL Password Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to read sensitive
  information via the HTTP 'Referrer' header.
  Impact Level: Application";
tag_affected = "Bugzilla version 3.4rc1 to 3.4.1.";
tag_insight = "The flaw is caused because the application places a password in a 'URL' at the
  beginning of a login session that occurs immediately after a password reset,
  which allows context-dependent attackers to discover passwords.";
tag_solution = "Upgrade to Bugzilla version 3.4.2 or later.
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "This host is running Bugzilla and is prone to information disclosure
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801413");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-3166");
  script_bugtraq_id(36372);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Bugzilla URL Password Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36718");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022902.html");

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

## Get version from KB
vers = get_version_from_kb(port:port, app:"bugzilla/version");
if(!vers){
 exit(0);
}

## Check Bugzilla version
if(version_in_range(version:vers, test_version: "3.4.rc1", test_version2:"3.4.1")){
 security_message(port:port);
}
