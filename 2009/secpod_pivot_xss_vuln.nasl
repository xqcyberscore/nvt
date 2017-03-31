###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivot_xss_vuln.nasl 5122 2017-01-27 12:16:00Z teissa $
#
# Pivot Cross Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to bypass
security restrictions by gaining sensitive information, exectue arbitrary
html or webscript code and redirect the user to other malicious sites.

Impact Level: Application";

tag_affected = "Pivot version 1.40.7 and prior.";

tag_insight = "
 - The input passed into several parameters in the pivot/index.php and
   pivot/user.php is not sanitised before being processed.
 - An error in pivot/tb.php while processing invalid url parameter reveals
   sensitive information such as the installation path in an error message.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Pivot and is prone to Cross Site
Scripting vulnerability.";

if(description)
{
  script_id(900579);
  script_version("$Revision: 5122 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-27 13:16:00 +0100 (Fri, 27 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2133", "CVE-2009-2134");
  script_bugtraq_id(35363);
  script_name("Pivot Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35363");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8941");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_pivot_detect.nasl");
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

pivotPort = get_http_port(default:80);
if(!pivotPort){
  exit(0);
}

pivotVer = get_kb_item("www/" + pivotPort + "/Pivot");
pivotVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pivotVer);

if(pivotVer[2] != NULL)
{
  if(!safe_checks())
  {
    sndReq = http_get(item:string(pivotVer[2],'/pivot/index.php?menu=">'+
                      '<script>alert(123)</script><br'),port:pivotPort);
    rcvRes = http_send_recv(port:pivotPort, data:sndReq);
    if(rcvRes =~ "HTTP/1\.. 200" && ("post" >< rcvRes) && ("<script>alert(123)</script>" >< rcvRes))
    {
      security_message(pivotPort);
      exit(0);
    }
  }
}

if(pivotVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:pivotVer[1], test_version:"1.40.7")){
  security_message(pivotPort);
}
