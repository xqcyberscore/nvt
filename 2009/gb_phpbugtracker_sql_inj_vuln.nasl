###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbugtracker_sql_inj_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# phpBugTracker 'index.php' SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the
underlying database.

Impact Level: Application";

tag_affected = "phpBugTracker 1.0.3 and prior on all running platform.";

tag_insight = "The flaw is due to error in 'index.php', it fails to
sufficiently sanitize user-supplied data before using it in an SQL query.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running phpBugTracker and is prone to SQL Injection
Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800621");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1850");
  script_bugtraq_id(35101);
  script_name("phpBugTracker 'index.php' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8808");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50752");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("phpBugTracker_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

bugtrackport = get_http_port(default:80);
if(!bugtrackport){
  exit(0);
}

bugtrackVer = get_kb_item("www/"+ bugtrackport + "/phpBugTracker");
if(!bugtrackVer){
  exit(0);
}

bugtrackVer = eregmatch(pattern:"^(.+) under (/.*)$", string:bugtrackVer);
if(bugtrackVer[1] != NULL)
{
  if(version_is_less_equal(version:bugtrackVer[1], test_version:"1.0.3")){
    security_message(bugtrackport);
  }
}
