###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_BSI-TR-03116-4_violation.nasl 7783 2017-11-16 08:20:50Z cfischer $
#
# List negative results from Policy for BSI-TR-03116-4 Test
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

# kb: Keep above the description part as it is used there
include("gos_funcs.inc");
include("version_func.inc");
gos_version = get_local_gos_version();
if( strlen( gos_version ) > 0 &&
    version_is_greater_equal( version:gos_version, test_version:"4.2.4" ) ) {
  use_severity = TRUE;
}

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96179");
  script_version("$Revision: 7783 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-16 09:20:50 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name:"creation_date", value:"2016-03-07 09:23:42 +0100 (Mon, 07 Mar 2016)");
  if( use_severity ) {
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }
  script_name("BSI-TR-03116-4: Violations");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("policy_BSI-TR-03116-4.nasl");
  script_mandatory_keys("policy/BSI-TR-03116-4/fail", "ssl_tls/port");

  script_tag(name:"summary", value:"List negative results from Policy for BSI-TR-03116-4 Test");
  script_tag(name:"insight", value:"Mindestens zu unterstützenden Cipher Suites:

  - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

  - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  Sofern anwendungsbezogen Cipher Suites eingesetzt werden, bei denen zusätzlich
  zur Authentisierung des Servers via Zertifikaten vorab ausgetauschte Daten
  (Pre-Shared-Key; PSK) in die Authentisierung und Schlüsseleinigung einfließen,
  muss mindestens die folgende Cipher Suite unterstützt werden:

  - TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

sslPort = get_ssl_port();
if( ! sslPort ) exit( 0 );

result = get_kb_item( "policy/BSI-TR-03116-4/" + sslPort + "/fail" );

if( result ) {
  if( use_severity )
    security_message( port:sslPort, data:report );
  else
    log_message( port:sslPort, data:report );
}

exit( 0 );
