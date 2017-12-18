###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftp_anonymous.nasl 8146 2017-12-15 13:40:59Z cfischer $
#
# Check for Anonymous FTP Login
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Modified 2009-03-24 by Michael Meyer
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900600");
  script_version("$Revision: 8146 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:40:59 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #script_cve_id("CVE-1999-0497");
  script_name("Check for Anonymous FTP Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0497");

  tag_summary = "This FTP Server allows anonymous logins.";

  tag_insight = "A host that provides an FTP service may additionally provide Anonymous FTP
  access as well. Under this arrangement, users do not strictly need an account
  on the host. Instead the user typically enters 'anonymous' or 'ftp' when
  prompted for username. Although users are commonly asked to send their email
  address as their password, little to no verification is actually performed on
  the supplied data.";

  tag_impact = "Based on the files accessible via this anonymous FTP login and the permissions
  of this account an attacker might be able to:

  - gain access to sensitive files

  - upload or delete files";

  tag_solution = "If you do not want to share files, you should disable anonymous logins.";

  tag_vuldetect = "Try to login with an anonymous account at the remove FTP service.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"vuldetect", value:tag_vuldetect);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

report = 'It was possible to login to the remote FTP service with the following anonymous account:\n\n';
listingReport = '\nHere are the contents of the remote FTP directory listing:\n';

ftpPort = get_ftp_port( default:21 );

domain = get_kb_item( "Settings/third_party_domain" );
if( isnull( domain ) ) {
  domain = this_host_name();
}

passwd = string( "openvas@", domain );

foreach user( make_list( "anonymous", "ftp" ) ) {

  soc1 = open_sock_tcp( ftpPort );
  if( ! soc1 ) exit( 0 );

  login_details = ftp_log_in( socket:soc1, user:user, pass:passwd );
  if( login_details ) {

    vuln = TRUE;
    report += user + ':' + passwd + '\n';

    ftpPort2 = ftp_get_pasv_port( socket:soc1 );
    if( ftpPort2 ) {

      soc2 = open_sock_tcp( ftpPort2, transport:get_port_transport( ftpPort ) );
      if( soc2 ) {

        send( socket:soc1, data:'LIST /\r\n' );
        listing = ftp_recv_listing( socket:soc2 );

        if( listing && strlen( listing ) ) {
          listingAvailable = TRUE;
          listingReport += '\nAccount "' + user + '":\n\n' + listing;
        }
        close( soc2 );
      }
    }

    set_kb_item( name:"ftp/" + ftpPort + "/anonymous", value:TRUE );
    if( ! get_kb_item( "ftp/login" ) ) {
      set_kb_item( name:"ftp/login", value:user );
      set_kb_item( name:"ftp/password", value:passwd );
    }
  }
  close( soc1 );
}

if( vuln ) {
  if( listingAvailable ) report += listingReport;
  security_message( port:ftpPort, data:report );
  exit( 0 );
}


exit( 99 );
