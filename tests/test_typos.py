from aura import typos

# TODO: fix this test
def disabled_test_analyze_info_data():
    uri1 = 'pypi://requests2'
    uri2 = 'pypi://requests'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['similar_description'] is True
    assert ta.flags['same_docs'] is True
    assert ta.flags['same_homepage'] is True

    uri2 = 'pypi://simplejson'
    ta = typos.TypoAnalyzer(uri1, uri2)
    ta.analyze_info_data()
    assert ta.flags['similar_description'] is False
    assert ta.flags['same_homepage'] is False
