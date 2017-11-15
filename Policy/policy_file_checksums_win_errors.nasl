###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums_win_errors.nasl 7753 2017-11-14 10:57:07Z jschulte $
#
# List Windows File with checksum errors
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.96182");
  script_version("$Revision: 7753 $");
  script_name("Windows file Checksums: Errors");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-14 11:57:07 +0100 (Tue, 14 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-09-09 11:11:22 +0200 (Mon, 09 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("policy_file_checksums_win.nasl");
  script_mandatory_keys("policy/win_checksum_started");

  script_tag(name:"summary", value:"List Windows files with checksum errors (missing files or other errors)");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit( 0 );
}

md5error = get_kb_list( "policy/win_md5cksum_err" );
sha1error = get_kb_list( "policy/win_sha1cksum_err" );

general_errors = get_kb_list( "policy/win_general_err" );

if( md5error || sha1error ) {
  report = "The following files are missing or showed some errors during the check:\n\n";
  report += 'Filename|Result|Errorcode;\n';
  foreach error ( md5error ) {
    report += error + '\n';
  }
  foreach error ( sha1error ) {
    report += error + '\n';
  }
  log_message( data: report, port: 0, proto: "ssh" );
}

if( general_errors ) {
  error_report = "The following errors occured during the test for Windows file Checksums:\n\n";
  foreach error ( general_errors) {
    report += error + '\n';
  }
  log_message( data: report, port: 0 );
}

if( ! get_kb_item( "policy/win_no_timeout" ) ) {
  timeoutReport = "A timeout happened during the test for Windows file Checksums. " +
                  "Consider raising the script_timeout value of the NVT " +
                  "'File Checksums' " +
                  "(OID: 1.3.6.1.4.1.25623.1.0.103940)";
  log_message( port: 0, data: timeoutReport );
}


exit( 0 );
