function responseHandler(response) {
    return response.items;
}

var actionTemplate = _.template('<a class="btn btn-default" title="<%= title %>" href="<%= url %>"><span class="glyphicon <%= glyphicon %>"></span></a>');
var confirmActionTemplate = _.template('<button class="btn btn-default confirm" type="button" value="<%= url %>"><span class="glyphicon <%= glyphicon %>"></span></button>');

$('table').on('click', '.confirm', function() {
    if (confirm("Sicher?")) {
        window.location = $(this).attr('value');
    }
});

function actionFormatter(urls, row, index) {
    return _.map(perItemActions, function (action) {
        var template;
        if (action.confirm) {
            template = confirmActionTemplate;
        } else {
            template = actionTemplate;
        }
        return template({
            'title': action.title,
            'url': urls[action.action],
            'glyphicon': action.glyphicon
        });
    }).join('');
}