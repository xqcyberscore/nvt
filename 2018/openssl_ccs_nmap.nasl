###############################################################################
# OpenVAS Vulnerability Test
# $Id: openssl_ccs_nmap.nasl 1 2018-11-30 16:20:00 +0100 (Fri, 30 Nov 2018) $
#
# SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability via NMAP
#
# Authors:
# Daniel Craig <daniel.craig@xqcyber.com>
#
# Copyright:
# Copyright (c) 2018 XQ Cyber, https://www.xqcyber.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300026");
  script_version("$Revision: 1 $");
  script_bugtraq_id(67899);
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 16:20:00 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-30 16:20:00 +0100 (Fri, 30 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability via NMAP");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("SSL and TLS");
  script_tag(name:"insight", value:"OpenSSL does not properly restrict processing of ChangeCipherSpec
    messages, which allows man-in-the-middle attackers to trigger use of a
    zero-length master key in certain OpenSSL-to-OpenSSL communications, and
    consequently hijack sessions or obtain sensitive information, via a crafted
    TLS handshake, aka the 'CCS Injection' vulnerability.");
  script_tag(name:"affected", value:"OpenSSL before 0.9.8za,
    1.0.0 before 1.0.0m and
    1.0.1 before 1.0.1h");
  script_tag(name:"summary", value:"OpenSSL is prone to security-bypass vulnerability.");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssl_funcs.inc");

host = get_host_ip();
port = get_ssl_port();
if( ! port ) exit( 0 );

# Assemble the command
i = 0;
argv[i++] = "nmap";
argv[i++] = "-Pn";
argv[i++] = "-p";
argv[i++] = port;
argv[i++] = "--script";
argv[i++] = "ssl-ccs-injection";
argv[i++] = host;

# Run the constructed command
res = pread( cmd:"nmap", argv:argv);

if ("ssl-ccs-injection" >< res) {
  security_message (data:res, port:port);
}
