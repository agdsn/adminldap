function responseHandler(response) {
    return response.items;
}

var actionTemplate = _.template('<a class="btn btn-default" title="<%= title %>" href="<%= url %>"><span class="glyphicon <%= glyphicon %>"></span></a>');

function actionFormatter(value, row, index) {
    return _.map(value, function (url, action) {
        return actionTemplate({
            'title': itemActions[action].title,
            'url': url,
            'glyphicon': itemActions[action].glyphicon
        });
    }).join('');
}