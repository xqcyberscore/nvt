###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_home_folder_accessible.nasl 5867 2017-04-05 09:01:13Z teissa $
#
# Linux Home Folder Accessible
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111108");
  script_version("$Revision: 5867 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-05 11:01:13 +0200 (Wed, 05 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-07-06 16:00:00 +0200 (Wed, 06 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Linux Home Folder Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files of a linux home folder accessible
  at the webserver.");
  script_tag(name:"insight", value:"Currently the script is checking for the following files:
  - /.ssh/authorized_keys
  - /.ssh/known_hosts
  - /.ssh/identity
  - /.ssh/id_rsa
  - /.ssh/id_rsa.pub
  - /.ssh/id_dsa
  - /.ssh/id_dsa.pub
  - /.ssh/id_dss
  - /.ssh/id_dss.pub
  - /.ssh/id_ecdsa
  - /.ssh/id_ecdsa.pub
  - /.ssh/id_ed25519
  - /.ssh/id_ed25519.pub
  - /.mysql_history
  - /.sqlite_history
  - /.psql_history
  - /.sh_history
  - /.bash_history
  - /.profile
  - /.bashrc");
  script_tag(name:"vuldetect", value:"Check the response if files from a home folder are accessible.");
  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might
  be able to gather additional info.");
  script_tag(name:"solution", value:"A users home folder shouldn't be accessible via a webserver. Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#TODO: Update detection pattern with more possible matchings
files = make_array( "/.ssh/authorized_keys", "^(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)",
                    "/.ssh/known_hosts", "(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)",
                    "/.ssh/identity", "^SSH PRIVATE KEY FILE FORMAT",
                    "/.ssh/id_rsa", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_rsa.pub", "^ssh-rsa",
                    "/.ssh/id_dsa", "^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_dsa.pub", "^ssh-dsa",
                    "/.ssh/id_dss", "^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_dss.pub", "^ssh-dss",
                    "/.ssh/id_ecdsa", "^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ecdsa.pub", "^ecdsa-sha2-nistp256",
                    "/.ssh/id_ed25519", "^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ed25519.pub", "^ssh-ed25519",
                    "/.mysql_history", "^(INSERT INTO|insert into|DELETE FROM|delete from|DROP TABLE|drop table|CREATE DATABASE|create database|select all|SELECT ALL|GRANT ALL ON|grant all on|FLUSH PRIVILEGES|flush privileges)",
                    "/.sqlite_history", "^(\.tables|\.quit|\.databases|INSERT INTO|insert into|DELETE FROM|delete from|DROP TABLE|drop table|CREATE DATABASE|create database|select all|SELECT ALL)",
                    "/.psql_history", "^(INSERT INTO|insert into|DELETE FROM|delete from|DROP TABLE|drop table|CREATE DATABASE|create database|select all|SELECT ALL|GRANT ALL ON|grant all on)",
                    "/.sh_history", "^(grep|chmod|chown|iptables|ifconfig|history|touch|head|tail|mkdir|sudo)",
                    "/.bash_history", "^(grep|chmod|chown|iptables|ifconfig|history|touch|head|tail|mkdir|sudo)",
                    "/.profile", "^# ~/.profile:",
                    "/.bashrc", "^# ~/.bashrc:" );

report = 'The following files were identified:\n';

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + file;

    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:files[file] ) ) {
        report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
        found = TRUE;
    }
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
