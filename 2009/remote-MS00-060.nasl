###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS00-060.nasl 4702 2016-12-07 13:02:11Z cfi $
#
# Microsoft Security Bulletin (MS00-060)
# 'IIS Cross-Site Scripting' Vulnerabilities 
#
# Affected Software: 
# Microsoft Internet Information Server 4.0 
# Microsoft Internet Information Server 5.0 
#
# remote-MS00-060.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101000");
  script_version("$Revision: 4702 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 14:02:11 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-03-08 14:50:37 +0100 (Sun, 08 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0746", "CVE-2000-0746", "CVE-2000-1104");
  script_bugtraq_id(1594, 1595);
  script_name("Microsoft MS00-060 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  tag_summary = "Vulnerabilities in IIS 4.0 and 5.0 do not properly protect against cross-site scripting (CSS) attacks. 
  They allow a malicious web site operator to embed scripts in a link to a trusted site, 
  which are returned without quoting in an error message back to the client. 
  The client then executes those scripts in the same context as the trusted site.";

  tag_solution = "Microsoft has released a patch to correct these issues,
  Download locations for this patch:

  Internet Information Server 4.0:
  http://www.microsoft.com/downloads/details.aspx?FamilyId=FE95D9FC-D769-43F3-8376-FAA1D2ABC4F3&displaylang=en 
 
  Internet Information Server 5.0:
  http://www.microsoft.com/downloads/details.aspx?FamilyId=31734888-9C17-43F1-BFD9-FDA8FEAF6D68&displaylang=en";
 
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# build the malicious request
url = '/_vti_bin/shtml.dll/<script>alert(1)</script>';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the detection NVT

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res ) {
  if( ( "Microsoft-IIS" >< res ) && ( egrep( pattern:"HTTP/1.[01] 200", string:res, icase:TRUE ) ) && ( "<script>(1)</script>" >< res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );