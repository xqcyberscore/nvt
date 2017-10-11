###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpkp_missing.nasl 7391 2017-10-10 08:05:50Z cfischer $
#
# SSL/TLS: HTTP Public Key Pinning (HPKP) Missing
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108247");
  script_version("$Revision: 7391 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-10 10:05:50 +0200 (Tue, 10 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HTTP Public Key Pinning (HPKP) Missing");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpkp_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("hpkp/missing/port");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote web server is not enforcing HPKP.");

  script_tag(name:"solution", value:"Enable HPKP or add / configure the required directives correctly following the
  guides linked in the references.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hpkp/missing/port" ) ) exit( 0 );
max_age_missing = get_kb_item( "hpkp/max_age/missing/" + port );
max_age_zero    = get_kb_item( "hpkp/max_age/zero/" + port );
pin_missing     = get_kb_item( "hpkp/pin/missing/" + port );
pkp_banner      = get_kb_item( "hpkp/" + port + "/banner" );

if( max_age_missing ) {
  report = "The remote web server is sending a HPKP header but is missing the required 'max-age=' directive.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else if( max_age_zero ) {
  report = "The remote web server is sending a HPKP header but is defining a 'max-age=0' directive which disables HPKP for this host.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else if( pin_missing ) {
  report = "The remote web server is sending a HPKP header but is missing a (supported) 'pin-' directive. Note: Currently only pin-sha256 is defined/supported.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else {
  banner = get_kb_item( "www/banner/" + port + "/" );
  # Clean-up Banner from dynamic data so we don't report differences on the delta report
  pattern = '([Dd]ate: |[Ee]xpires=|[Ee]xpires: |PHPSESSID=|[Ll]ast-[Mm]odified: |[Cc]ontent-[Ll]ength: |[Ss]et-[Cc]ookie: |[Ee][Tt]ag: (W/"|")?|[Ss]ession[Ii]d=)([0-9a-zA-Z :,-;=]+)';
  if( eregmatch( pattern:pattern, string:banner ) ) {
    banner = ereg_replace( string:banner, pattern:pattern, replace:"\1***replaced***" );
  }
  report = "The remote web server is not enforcing HPKP.";
  report += '\n\nHTTP-Banner:\n\n' + banner;
}

log_message( port:port, data:report );
exit( 0 );
