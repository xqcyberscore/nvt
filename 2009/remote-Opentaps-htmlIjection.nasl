###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-Opentaps-htmlIjection.nasl 4455 2016-11-09 11:42:46Z cfi $
#
# Opentaps Search_String Parameter HTML Injection Vulnerability (BID 21702)
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101022");
  script_version("$Revision: 4455 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-09 12:42:46 +0100 (Wed, 09 Nov 2016) $");
  script_tag(name:"creation_date", value:"2009-04-24 21:45:26 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6589");
  script_bugtraq_id(21702);
  script_name("Opentaps ERP + CRM Search_String Parameter HTML injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "remote-detect-Opentaps_ERP_CRM.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("OpentapsERP/installed");

  tag_summary = "The running Opentaps ERP + CRM is prone to the HTML Injection Vulnerability";

  tag_solution = "Download the latest release form opentaps website (http://www.opentaps.org)";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix"); 
  script_tag(name:"qod_type", value:"remote_banner"); 

  exit(0);

}

include("revisions-lib.inc");
include("misc_func.inc");

if( ! port = get_kb_item( "OpentapsERP/port" ) ) exit( 0 );
if( ! version = get_kb_item( "OpentapsERP/version" ) ) exit( 0 );

if( revcomp( a:version, b:"0.9.3" ) <= 0 ) {
  # report Opentaps ERP + CRM Search_String Parameter HTML Injection Vulnerability
  report = "The current Opentaps version " + version + " is affected by a Search_String Parameter HTML injection vulnerability";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );