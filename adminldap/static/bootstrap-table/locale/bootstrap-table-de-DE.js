/**
 * Bootstrap Table German translation
 * Author: Sebastian Schrader <sebastian.schrader@ossmail.de>
 */
(function ($) {
    'use strict';

    $.extend($.fn.bootstrapTable.defaults, {
        formatLoadingMessage: function () {
            return 'Lade, bitte warten…';
        },
        formatRecordsPerPage: function (pageNumber) {
            return pageNumber + ' Einträge pro Seite';
        },
        formatShowingRows: function (pageFrom, pageTo, totalRows) {
            return 'Zeige ' + pageFrom + ' bis ' + pageTo + ' von ' + totalRows + ' Einträgen';
        },
        formatSearch: function () {
            return 'Suche';
        },
        formatNoMatches: function () {
            return 'Keine passenden Einträge gefunden';
        }
    });
})(jQuery);
 
