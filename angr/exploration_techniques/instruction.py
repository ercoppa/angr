from angr.exploration_techniques import ExplorationTechnique

import collections

class InstructionExplorer(ExplorationTechnique):
    '''
    This exploration technique should be nested with 
    angr.exploration_techniques.Explorer. E.g.:

        pg = angr.PathGroup(...) 
        tech = InstructionExplorer(max_active=1)
        pg.use_technique(tech)
        ex = pg.explore(...)

    It is designed to resemble the exploration performed by surveyors.Explorer.
    An instruction counter is updated during exploration: whenever a new path is 
    reached, the counter is increased by one for each instruction address contained 
    in basic block of the path. Each execution round, paths are sorted based on this 
    counter, and only a subset of them (i.e., max_active of them) is actually explored 
    in the current round. Unselected paths are inserted into a stash called 'deferred'.
    '''

    def __init__(self, max_active=1):
        """
        :param max_active:  max number of path that will be kept as active
        """
        super(InstructionExplorer, self).__init__()
        self.max_active = max_active
        self.instruction_counter = collections.Counter()

    def setup(self, pg):

        self.pg = pg
        if 'deferred' not in pg.stashes: 
            pg.stashes['deferred'] = []
        else:
            for p in pg.stashes['deferred']:
                self.increment_counter(p)            

        for p in pg.stashes['active']:
            self.increment_counter(p)

    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)

        prioritized = self.prioritize_paths(pg.stashes[stash] + pg.stashes['deferred'])
        pg.stashes[stash] = prioritized[:self.max_active]
        pg.stashes['deferred'] = prioritized[self.max_active:]

        return pg

    def step_path(self, path, **kwargs):

        hook = self.pg._hooks_step_path.pop()
        successors = self.pg._one_path_step(a=path, **kwargs)
        self.pg._hooks_step_path.append(hook)

        for p in successors[0]:
            self.increment_counter(p)

        return successors

    def prioritize_paths(self, paths):
        paths.sort(cmp=self.path_comparator)
        return paths

    def path_comparator(self, x, y):
        return self.instruction_counter[x.addr] - self.instruction_counter[y.addr]

    def increment_counter(self, p):

        if not self.project.is_hooked(p.addr):
            try:
                imark_set = set(self.project.factory.block(p.addr).instruction_addrs)
            except (AngrMemoryError, AngrTranslationError):
                return
        else:
            imark_set = { p.addr }

        for addr in imark_set:
            self.instruction_counter[addr] += 1