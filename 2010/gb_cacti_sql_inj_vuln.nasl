##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_sql_inj_vuln.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Cacti 'export_item_id' Parameter SQL Injection Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to access, modify or delete
  information in the underlying database.
  Impact Level: Application.";
tag_affected = "Cacti version 0.8.7e and prior.";

tag_solution = "Apply the patch from below link,
  http://www.cacti.net/downloads/patches/0.8.7e/sql_injection_template_export.patch

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_insight = "Input passed to the 'templates_export.php' script via 'export_item_id' is
  not properly sanitized before being used in a SQL query.";
tag_summary = "This host is running Cacti and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800772");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1431");
  script_bugtraq_id(39653);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cacti 'export_item_id' Parameter SQL Injection Vulnerability");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0986");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=578909");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/sploits/Bonsai-SQL_Injection_in_Cacti.pdf");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

ctPort = get_http_port(default:80);
if(!get_port_state(ctPort)){
  exit(0);
}

## Get Cacti version from KB
ctVer = get_kb_item("www/"+ ctPort + "/cacti");
if(!ctVer){
 exit(0);
}

## Check for the Cacti version
if(ctVer[1] != NULL)
{
  if(version_is_less_equal(version:ctVer[1], test_version:"0.8.7e")){
    security_message(ctPort);
  }
}
