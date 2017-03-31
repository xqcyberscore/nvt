#############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mdaemon_script_insertion_vuln_900405.nasl 4522 2016-11-15 14:52:19Z teissa $
#
# MDaemon Server WordClient Script Insertion Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900405");
  script_version("$Revision: 4522 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-15 15:52:19 +0100 (Tue, 15 Nov 2016) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6967");
  script_bugtraq_id(32355);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("MDaemon Server WordClient Script Insertion Vulnerability");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  script_xref(name:"URL", value:"http://secunia.com/advisories/32142");
  script_xref(name:"URL", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");

  script_tag(name:"impact", value:"Attacker can execute malicious arbitrary codes in the email body.
  Impact Level: Application.");
  script_tag(name:"affected", value:"MDaemon Server version prior to 10.0.2.");
  script_tag(name:"insight", value:"This vulnerability is due to input validation error in 'HTML tags' in
  emails are not properly filtered before displaying. This can be exploited when the malicious email is viewed.");
  script_tag(name:"solution", value:"Upgrade to the latest version 10.0.2.
  http://www.altn.com/Downloads/FreeEvaluation");
  script_tag(name:"summary", value:"This host is installed with MDaemon and is prone to script insertion
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");

port = get_smtp_port( default:25 );
banner = get_smtp_banner( port:port );

if( "MDaemon" >!< banner ) exit( 0 );

#Grep for WorldClient version 10.0.1 or prior
if( egrep( pattern:"MDaemon .* [0-9]\..*|10\.0\.[01]" , string:banner ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );