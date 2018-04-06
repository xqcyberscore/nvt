###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_policy_manager_xss_n_path_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# F-Secure Policy Manager 'WebReporting' Module XSS And Path Disclosure Vulnerabilities
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

tag_solution = "F-Secure Policy Manager for Windows version 8.00 - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.00-windows-hotfix-2.zip

  F-Secure Policy Manager for Windows version 8.1x - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.1x-windows-hotfix-3.zip

  F-Secure Policy Manager for Windows version 9.00 - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-9.00-windows-hotfix-4.zip

  F-Secure Policy Manager for Linux version 8.00 - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.00-linux-hotfix-2.zip

  F-Secure Policy Manager for Linux version 8.1x - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.1x-linux-hotfix-2.zip

  F-Secure Policy Manager for Linux version 9.00 - Apply patch:
  ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-9.00-linux-hotfix-2.zip";

tag_impact = "Successful exploitation will allow attacker to disclose potentially sensitive
  information and execute arbitrary code in the context of an application.
  Impact Level: Application";
tag_affected = "F-Secure Policy Manager versions 7.x, 8.x and 9.x";
tag_insight = "The flaws are caused by an error in the 'WebReporting' interface when
  processing user-supplied requests, which could allow cross-site scripting
  and path disclosure attacks.";
tag_summary = "This host is running F-Secure Policy Manager and is prone to cross
  site scripting and path disclosure vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801852");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-1102", "CVE-2011-1103");
  script_bugtraq_id(46547);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("F-Secure Policy Manager 'WebReporting' Module XSS And Path Disclosure Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/43049");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1025124");
  script_xref(name : "URL" , value : "http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-2.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);
res = http_get_cache(item:"/",  port:port);

## Confirm the application
if(">F-Secure Policy Manager Web Reporting<" >< res)
{
  ## Try XSS and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:"/%3Cscript%3Ealert(%27openvas-xss-testing%27)%3C/script%3E",
                     pattern:"<script>alert\('openvas-xss-testing'\)</script>", check_header:TRUE)){
    security_message(port);
  }
}
