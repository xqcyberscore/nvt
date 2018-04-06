###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bugtracker_dotnet_xss_n_sql_injection_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# BugTracker.NET Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and to conduct cross-site scripting attacks.
  Impact Level: Application";
tag_affected = "BugTracker.NET version prior to 3.4.5";
tag_insight = "The flaws are due to:
  - Input passed to the 'pcd' parameter in edit_bug.aspx, 'bug_id' parameter
    in edit_comment.aspx, 'default_name' parameter in edit_customfield.aspx,
    and 'id' parameter in edit_user_permissions2.aspx is not properly sanitised
    before being returned to the user.
  - Input passed via the 'qu_id' parameter to bugs.aspx, 'row_id' parameter to
    delete_query.aspx, 'us_id' and 'new_project' parameters to edit_bug.aspx,
    and 'bug_list' parameter to massedit.aspx is not properly sanitised before
    being used in a SQL query.";
tag_solution = "Upgrade to BugTracker.NET version 3.4.5 or later,
  For updates refer to http://www.ifdefined.com/bugtrackernet_download.html";
tag_summary = "The host is running BugTracker.NET and is prone to cross-site
  scripting and SQL injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902407");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_bugtraq_id(45121);
  script_cve_id("CVE-2010-3266", "CVE-2010-3267");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("BugTracker.NET Cross-Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42418");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15653/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514957/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/multiple-vulnerabilities-in-bugtracker");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_bugtracker_detect.nasl");
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

## Get BugTracker Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check for BugTracker.NET version prior to 3.4.5
if(ver = get_version_from_kb(port:port,app:"btnet"))
{
  if(version_is_less(version:ver, test_version: "3.4.5")){
    security_message(port:port);
  }
}
