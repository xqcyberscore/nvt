###############################################################################
# OpenVAS Include File
# $Id: products_eol.inc 6432 2017-06-26 13:16:02Z cfischer $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
#
# $Revision: 6432 $
#
###############################################################################

eol_cpes = make_array();

# https://github.com/owncloud/core/wiki/Maintenance-and-Release-Schedule
eol_cpes[ 'cpe:/a:owncloud:owncloud' ]       = make_array(
                                                           'versions',      '8.2:2017-05-31;8.1:2017-02-28;8.0:2016-10-31;7.0:2016-05-31;6.0:2015-09-01;5.0:2015-03-01;4.5:2013-07-01;4.0:2013-07-01;3.0:2012-04-01;2.0:2012-01-01;1.0:2011-10-01',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://www.postgresql.org/support/versioning/
eol_cpes[ 'cpe:/a:postgresql:postgresql']    = make_array(
                                                           'versions',      '9.6:2021-09-01;9.5:2021-01-01;9.4:2019-12-01;9.3:2018-09-01;9.2:2017-09-01;9.1:2016-09-01;9.0:2015-09-01;8.4:2014-07-01;8.3:2013-02-01;8.2:2011-12-01;8.1:2010-11-01;8.0:2010-10-01;7.4:2010-10-01;7.3:2007-11-01;7.2:2007-02-01;7.1:2006-04-01;7.0:2005-05-01;6.5:2004-06-01;6.4:2003-10-01;6.3:2003-03-01',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://wiki.samba.org/index.php/Samba_Release_Planning
eol_cpes[ 'cpe:/a:samba:samba' ]             = make_array(
                                                           'versions',      '4.3:2017-03-07;4.2:2016-09-07;4.1:2016-03-22;4.0:2015-09-08;3.6:2015-03-04;3.5:2013-10-11;3.4:2012-12-11;3.3:2011-08-09;3.2:2010-03-01;3.0:2009-08-05',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://tomcat.apache.org/whichversion.html
eol_cpes[ 'cpe:/a:apache:tomcat' ]           = make_array(
                                                           'versions',      '6.0:2016-12-31;5.5:2012-09-30;5.0:2004-08-30;4.1:2009-06-25;4.0:2009-06-25;3.3:2004-03-09;3.2:2004-03-09;3.1:2004-03-09;3.0:2004-03-09',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://en.wikipedia.org/wiki/Apache_HTTP_Server#Development
eol_cpes[ 'cpe:/a:apache:http_server' ]      = make_array(
                                                           'versions',      '2.0:2013-07-10;1.3:2010-02-03',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# IIS EOL dates are mostly coupled to the EOL of the OS, see os_eol.inc
eol_cpes[ 'cpe:/a:microsoft:iis' ]           = make_array(
                                                           'versions',      '6.0:2015-07-14;5.1:2014-04-08;5.0:2010-07-13;4.0:2002-12-31;3.0:2002-12-31;2.0:2002-12-31;1.0:2000-09-30',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://secure.php.net/eol.php and https://secure.php.net/supported-versions.php
eol_cpes[ 'cpe:/a:php:php' ]                 = make_array(
                                                           'versions',      '7.1:2019-12-01;7.0:2018-12-03;5.6:2018-12-31;5.5:2016-07-21;5.4:2015-09-03;5.3:2014-08-14;5.2:2011-01-06;5.1:2006-08-24;5.0:2005-09-05;4.4:2008-08-07;4.3:2005-03-31;4.2:2002-09-06;4.1:2002-03-12;4.0:2001-06-23;3.0:2000-10-20',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://mariadb.org/about/maintenance-policy/
eol_cpes[ 'cpe:/a:mariadb:mariadb' ]         = make_array(
                                                           'versions',      '10.2:2022-05-23;10.1:2020-10-17;10.0:2019-03-31;5.5:2020-04-11;5.3:2017-03-01;5.2:2015-11-10;5.1:2015-02-01',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sql%20server&Filter=FilterNO
# https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary
# TODO: We shouldn't use the release version but the release name for the CPE instead (see gb_windows_cpe_detect.nasl)
eol_cpes[ 'cpe:/a:microsoft:sql_server' ]    = make_array(
                                                           'versions',      '10.50:2019-07-09;10.0:2019-07-09;9.0:2016-04-12;8.0:2014-04-09;7.0:2011-01-11;6.5:2004-03-31;6.0:1999-03-31;4.2:1999-07-01',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

# mysql:mysql is <= 5.5.9, newer versions have oracle:mysql
# https://en.wikipedia.org/wiki/MySQL#Release_history
# https://www.mysql.com/support/eol-notice.html (Sustaining Support means EOL)
eol_cpes[ 'cpe:/a:mysql:mysql' ]             = make_array(
                                                           'versions',      '5.1:2013-12-04;5.0:2012-01-09;4.1:2009-12-31;4.0:2008-12-31;3.2:2006-08-01',
                                                           'version_regex', '^([0-9]+\\.[0-9]+)'
                                                         );

function product_reached_eol( cpe, version ) {

  local_var cpe, version, eol_array, v, test_versions, tv, test_version, eol_date, v_d;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#product_reached_eol" );
    return;
  }

  if( ! eol_cpes[ cpe ] ) {
    set_kb_item( name:"nvt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#product_reached_eol" );
    return;
  }

  if( ! version ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#product_reached_eol" );
    return;
  }

  eol_array = eol_cpes[ cpe ];

  if( ! is_array( eol_array ) )
    return;

  if( ! eol_array[ 'versions' ] )
    return;

  if( eol_array[ 'version_regex' ] ) {

    v = eregmatch( pattern:eol_array[ 'version_regex' ], string:version );
    if( isnull( v[1] ) )
      return;

    version = v[ max_index( v ) - 1 ];
  }

  test_versions = split( eol_array[ 'versions' ], sep:';', keep:FALSE );
  if( ! is_array( test_versions ) )
    return;

  foreach tv ( test_versions ) {

    test_version = '';
    eol_date     = '';

    v_d = eregmatch( pattern:'^([^:]+):(.*)$', string:tv );
    if( isnull( v_d[1] ) || isnull( v_d[2] ) )
      return;

    test_version = v_d[1];
    eol_date     = v_d[2];

    if( version == test_version )
      if( eol_date_reached( eol_date:eol_date ) )
        return make_array( 'eol_version', test_version,
                           'eol_date',    eol_date
                         );
  }

  return;
}

function eol_date_reached( eol_date ) {

  local_var eol_date, local_time;

  if( ! eol_date ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#eol_date_reached" );
    return;
  }

  eol_date = str_replace( string:eol_date, find:"-", keep:FALSE );
  local_time = make_date_str( date:localtime( unixtime() ) );

  if( int( local_time ) >= int( eol_date ) )
    return TRUE;

  return;
}

function make_date_str( date ) {

  time = localtime(date);

  month  = fancy_date ( time["mon"]  );
  day    = fancy_date ( time["mday"] );

  return time["year"] + month + day;
}

function fancy_date() {

  local_var datestr;

  datestr =  _FCT_ANON_ARGS[0];
  if (int (datestr ) < 10) return string ("0", datestr);

  return datestr;
}
