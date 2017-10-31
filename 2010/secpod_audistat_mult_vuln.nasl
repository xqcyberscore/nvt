###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_audistat_mult_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# AudiStat multiple vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow the attackers to inject
arbitrary SQL code, execute arbitrary HTML and script code on the vulnerable
system.

Impact Level: Application";

tag_affected = "AudiStat version 1.3 and prior";

tag_insight = "Input passed to the 'year', 'month' and 'mday' parameters in
index.php are not properly sanitised before being returned to the user or
before being used in the sql queries.";

tag_solution =  "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running AudiStat and is prone to multiple
vulnerabilities.";

if(description)
{
  script_id(902029);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1050", "CVE-2010-1051", "CVE-2010-1052");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AudiStat multiple vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38494");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11334");

  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_audistat_detect.nasl");
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

# Check AudiStat is running
statPort = get_http_port(default:80);
if(!statPort){
  exit(0);
}

## Get version and installed path from KB
statVer = get_kb_item("www/" + statPort + "/Audistat");
if(isnull(statVer)){
 exit(0);
}

statVer = eregmatch(pattern:"^(.+) under (/.*)$", string:statVer);
if(!isnull(statVer[2]))
{
  ## Checking for the exploit on AudiStat
  sndReq = http_get(item:string(statVer[2], "/?year=kaMtiEz&month=tukulesto" +
                    "&mday=<script>alert('OpenVAS-XSS-Testing')</script>"),
                    port:statPort);
  rcvRes = http_send_recv(port:statPort, data:sndReq);
  if(rcvRes =~ "HTTP/1\.. 200" && "OpenVAS-XSS-Testing" >< rcvRes)
  {
    security_message(statPort);
    exit(0);
  }
}
